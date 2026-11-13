//! Login records of OpenBSD and NetBSD: `utmp`, `wtmp` and `lastlog` (the original BSD
//! structures, utmp(5) and lastlog(5)) and NetBSD's `utmpx`, `wtmpx` (utmpx(5)).
//!
//! `struct utmp` is `line[8]`, `name`, `host`, `time`: OpenBSD has a 32-byte name, a 256-byte
//! host and a 64-bit time (304 bytes; 300 with a 32-bit time before OpenBSD 5.5), NetBSD an 8-byte
//! name, a 16-byte host and a 64-bit time (40 bytes). The integers are in the byte order of the
//! machine that wrote them, which the file does not say: the layout and the order are chosen
//! by which make the times plausible and the file length a whole number of records.
//! `struct lastlog` is `time`, `line[8]`, `host`, one per UID: indexed by user id, with the
//! name from `etc/passwd`.
//!
//! A `wtmp` record is a login (a name), a logout (an empty name on the line), or a system
//! event: line `~` with name `reboot` or `shutdown`, `|` and `{` for the clock before and
//! after a change. `struct utmpx` (NetBSD) is 520 bytes (see `UTMPX_SIZE`).
//!
//! `lastlogx` is a Berkeley DB 1.85 hash file and is not read.

use crate::linux::utmp::field;
use crate::text::decompressed;
use crate::{Artifact, Category, Input, NETBSD};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Os;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

/// FreeBSD keeps `utx.*` instead (see `utx`).
const OPENBSD_NETBSD: &[Os] = &[Os::OpenBsd, Os::NetBsd];

pub const UTMP: Artifact = Artifact::new(
    "bsd-utmp",
    "OpenBSD and NetBSD logins, logouts and boots (utmp, wtmp)",
    Category::Accounts,
    OPENBSD_NETBSD,
    &["var/run/utmp", "var/log/wtmp", "var/log/wtmp.*"],
    parse_utmp,
);

pub const LASTLOG: Artifact = Artifact::new(
    "bsd-lastlog",
    "OpenBSD and NetBSD last login per user (lastlog)",
    Category::Accounts,
    OPENBSD_NETBSD,
    &["var/log/lastlog"],
    parse_lastlog,
)
.companions(&["etc/passwd"]);

pub const UTMPX: Artifact = Artifact::new(
    "netbsd-utmpx",
    "NetBSD logins, logouts and boots (utmpx, wtmpx)",
    Category::Accounts,
    NETBSD,
    &["var/run/utmpx", "var/log/wtmpx", "var/log/wtmpx.*"],
    parse_utmpx,
);

#[derive(Clone, Copy)]
struct Layout {
    size: usize,
    name: usize,
    host: usize,
    time: usize,
    wide: bool,
}

const OPENBSD64: Layout = Layout { size: 304, name: 32, host: 256, time: 8, wide: true };
const OPENBSD32: Layout = Layout { size: 300, name: 32, host: 256, time: 4, wide: false };
const NETBSD_UTMP: Layout = Layout { size: 40, name: 8, host: 16, time: 8, wide: true };

/// 1990-01-01 and 2100-01-01: what a login time can be.
const PLAUSIBLE: std::ops::Range<i64> = 631_152_000..4_102_444_800;

fn int(bytes: &[u8], wide: bool, big: bool) -> i64 {
    match (wide, big) {
        (true, true) => i64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
        (true, false) => i64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
        (false, true) => i64::from(i32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4]))),
        (false, false) => i64::from(i32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]))),
    }
}

/// Records whose time is plausible under this layout and byte order, minus the others
/// (an empty slot, time 0, says nothing).
fn score(data: &[u8], layout: Layout, big: bool, time_at: usize) -> i64 {
    data.chunks_exact(layout.size)
        .map(|r| match r.get(time_at..time_at + layout.time) {
            Some(t) => match int(t, layout.wide, big) {
                0 => 0,
                v if PLAUSIBLE.contains(&v) => 1,
                _ => -1,
            },
            None => -1,
        })
        .sum()
}

/// The layout, and whether it is big-endian. A length that only one layout divides decides;
/// otherwise the layout and order with the most plausible times win, ties going to OpenBSD
/// 64-bit little-endian.
fn detect(data: &[u8], candidates: &[Layout], time_at: impl Fn(Layout) -> usize) -> Option<(Layout, bool)> {
    let fitting: Vec<Layout> = candidates.iter().copied().filter(|l| data.len() % l.size == 0).collect();
    let pool = if fitting.is_empty() { candidates } else { &fitting[..] };
    let mut best: Option<(i64, Layout, bool)> = None;
    for &layout in pool {
        for big in [false, true] {
            let s = score(data, layout, big, time_at(layout));
            if best.is_none_or(|(b, _, _)| s > b) {
                best = Some((s, layout, big));
            }
        }
    }
    best.map(|(_, l, b)| (l, b))
}

#[derive(Serialize)]
struct Login<'a> {
    time: Timestamp,
    /// `login`, `logout`, `boot`, `shutdown`, `old_time` or `new_time`.
    #[serde(rename = "type")]
    kind: &'static str,
    user: Cow<'a, str>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
}

impl Record for Login<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let (kind, message) = match self.kind {
            "login" => ("login", format!("{} logged in on {} from {from}", self.user, self.line)),
            "logout" => ("logout", format!("session ended on {}", self.line)),
            "boot" => ("boot", "system boot".to_string()),
            "shutdown" => ("shutdown", "system shutdown".to_string()),
            _ => ("time_change", format!("system clock changed ({})", self.kind)),
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

fn parse_utmp(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let Some((layout, big)) = detect(&data, &[OPENBSD64, NETBSD_UTMP, OPENBSD32], |l| 8 + l.name + l.host) else {
        return Err(Error::format("no utmp layout fits"));
    };
    if data.len() % layout.size != 0 {
        sink.warn(format!("size {} is not a multiple of {}; trailing bytes ignored", data.len(), layout.size));
    }
    let time_at = 8 + layout.name + layout.host;
    for (index, r) in data.chunks_exact(layout.size).enumerate() {
        let offset = (index * layout.size) as u64;
        let line = &r[..8];
        let name = &r[8..8 + layout.name];
        let host = &r[8 + layout.name..time_at];
        let secs = int(&r[time_at..], layout.wide, big);
        if line.iter().all(|&b| b == 0) && name.iter().all(|&b| b == 0) && secs == 0 {
            continue; // empty slot
        }
        let Some(time) = Timestamp::checked(secs, 0, Precision::Seconds, Basis::Recorded).filter(|_| secs >= 0) else {
            sink.warn(format!("offset {offset}: time {secs} is out of range"));
            continue;
        };
        let (line, user) = (field(line), field(name));
        let kind = match (&*line, &*user) {
            ("~", "reboot") => "boot",
            ("~", "shutdown") => "shutdown",
            ("|", _) => "old_time",
            ("{", _) => "new_time",
            (_, "") => "logout",
            _ => "login",
        };
        sink.emit(Loc::Offset(offset), &Login { time, kind, user, line, remote_host: field(host) })?;
    }
    Ok(())
}

#[derive(Serialize)]
struct LastLogin<'a> {
    uid: u64,
    /// From `etc/passwd`; empty when the UID is not listed there.
    user: &'a str,
    time: Timestamp,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
}

impl Record for LastLogin<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let message = format!("{who} last logged in on {} from {from}", self.line);
        Some(Event::new(self.time, "last_login", message)).into_iter()
    }
}

/// `struct lastlog`: time, `line[8]`, host. OpenBSD 64-bit time (272 bytes), OpenBSD 32-bit
/// (268), NetBSD 64-bit (32), NetBSD before 64-bit time (28).
const LASTLOGS: [Layout; 4] = [
    Layout { size: 272, name: 0, host: 256, time: 8, wide: true },
    Layout { size: 268, name: 0, host: 256, time: 4, wide: false },
    Layout { size: 32, name: 0, host: 16, time: 8, wide: true },
    Layout { size: 28, name: 0, host: 16, time: 4, wide: false },
];

fn parse_lastlog(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let Some((layout, big)) = detect(data, &LASTLOGS, |_| 0) else {
        return Err(Error::format("no lastlog layout fits"));
    };
    let passwd = input.host.read_text("etc/passwd").unwrap_or_default();
    let mut users: HashMap<u64, &str> = HashMap::new();
    for line in passwd.lines().filter(|l| !l.starts_with('#')) {
        let mut f = line.split(':');
        if let (Some(name), Some(uid)) = (f.next(), f.nth(1).and_then(|v| v.parse().ok())) {
            users.entry(uid).or_insert(name);
        }
    }
    if data.len() % layout.size != 0 {
        sink.warn(format!("size {} is not a multiple of {}; trailing bytes ignored", data.len(), layout.size));
    }
    for (uid, r) in data.chunks_exact(layout.size).enumerate() {
        let secs = int(r, layout.wide, big);
        if secs == 0 {
            continue; // never logged in
        }
        let Some(time) = Timestamp::checked(secs, 0, Precision::Seconds, Basis::Recorded).filter(|_| secs > 0) else {
            sink.warn(format!("uid {uid}: time {secs} is out of range"));
            continue;
        };
        let uid = uid as u64;
        sink.emit(
            Loc::Offset(uid * layout.size as u64),
            &LastLogin {
                uid,
                user: users.get(&uid).copied().unwrap_or_default(),
                time,
                line: field(&r[layout.time..layout.time + 8]),
                remote_host: field(&r[layout.time + 8..]),
            },
        )?;
    }
    Ok(())
}

/// NetBSD `struct utmpx` (utmpx.h), 520 bytes: `name[32]` at 0, `id[4]` at 32, `line[32]` at 36,
/// `host[256]` at 68, `session` (u16) at 324, `type` (u16) at 326, `pid` (u32) at 328, the exit
/// status at 332, a 128-byte socket address at 336, the time (seconds 8 bytes, microseconds
/// 4 bytes) at 464, and 40 reserved bytes.
const UTMPX_SIZE: usize = 520;

fn parse_utmpx(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if data.len() % UTMPX_SIZE != 0 {
        sink.warn(format!("size {} is not a multiple of {UTMPX_SIZE}; trailing bytes ignored", data.len()));
    }
    let chunks = || data.chunks_exact(UTMPX_SIZE);
    let plausible = |big: bool| -> i64 {
        chunks()
            .map(|r| match int(&r[464..], true, big) {
                0 => 0,
                v if PLAUSIBLE.contains(&v) => 1,
                _ => -1,
            })
            .sum()
    };
    let big = plausible(true) > plausible(false);
    for (index, r) in chunks().enumerate() {
        let offset = (index * UTMPX_SIZE) as u64;
        let secs = int(&r[464..], true, big);
        let kind_raw = if big { u16::from_be_bytes([r[326], r[327]]) } else { u16::from_le_bytes([r[326], r[327]]) };
        // Empty slots and the `utmpx-2.00` signature record that starts the file (time 0).
        if kind_raw == 0 || kind_raw == 10 {
            continue;
        }
        let micros = int(&r[472..], false, big).clamp(0, 999_999) as u32;
        let Some(time) =
            Timestamp::checked(secs, micros * 1000, Precision::Micros, Basis::Recorded).filter(|_| secs >= 0)
        else {
            sink.warn(format!("offset {offset}: time {secs} is out of range"));
            continue;
        };
        // NetBSD's utmpx type numbers (utmpx.h).
        let kind = match kind_raw {
            1 => "run_level",
            2 => "boot",
            3 => "old_time",
            4 => "new_time",
            5 => "init_process",
            6 => "login_process",
            7 => "login",
            8 => "logout",
            9 => "accounting",
            11 => "shutdown",
            _ => {
                sink.warn(format!("offset {offset}: unknown record type {kind_raw}"));
                continue;
            }
        };
        sink.emit(
            Loc::Offset(offset),
            &Login { time, kind, user: field(&r[..32]), line: field(&r[36..68]), remote_host: field(&r[68..324]) },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<serde_json::Value> {
        out.lines().take_while(|l| l.starts_with('{')).filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    fn truth(name: &str) -> Vec<Vec<String>> {
        let text = String::from_utf8(fixture(name)).unwrap_or_default();
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split('\t').map(str::to_string).collect()).collect()
    }

    fn iso(secs: i64) -> String {
        Timestamp::from_secs(secs, Basis::Recorded).to_rfc3339()
    }

    /// The first 10 records of an OpenBSD 7.8 `wtmp` (304-byte records, 64-bit times), against the libc dump.
    #[test]
    fn a_real_openbsd_wtmp_equals_the_libc_dump() {
        let out = run(&UTMP, "var/log/wtmp", &fixture("bsd-utmp/openbsd-wtmp"), 0);
        let (recs, truth) = (records(&out), truth("bsd-utmp/openbsd-wtmp.truth"));
        assert_eq!(recs.len(), truth.len(), "{out}");
        for (r, t) in recs.iter().zip(&truth) {
            let time = iso(t[3].parse().unwrap_or_default());
            assert_eq!(
                (r["line"].as_str(), r["user"].as_str(), r["remote_host"].as_str(), r["time"].as_str()),
                (Some(&t[0][..]), Some(&t[1][..]), Some(&t[2][..]), Some(&time[..])),
                "{r}"
            );
        }
        assert!(
            out.contains("\"type\":\"boot\"")
                && out.contains("\"type\":\"login\"")
                && out.contains("\"type\":\"logout\"")
        );
        assert!(!out.contains("--- warning"), "{out}");
    }

    /// `bsd-utmp/netbsd-wtmp` is the first 12 records of a NetBSD 10.1 `wtmp`; its `.truth` is the
    /// same file read with `fread()` of the libc's `struct utmp` (line, name, host, time).
    #[test]
    fn a_real_netbsd_wtmp_equals_the_libc_dump() {
        let out = run(&UTMP, "var/log/wtmp", &fixture("bsd-utmp/netbsd-wtmp"), 0);
        let (recs, truth) = (records(&out), truth("bsd-utmp/netbsd-wtmp.truth"));
        assert_eq!(recs.len(), truth.len(), "{out}");
        for (r, t) in recs.iter().zip(&truth) {
            let time = iso(t[3].parse().unwrap_or_default());
            assert_eq!(
                (r["line"].as_str(), r["user"].as_str(), r["remote_host"].as_str(), r["time"].as_str()),
                (Some(&t[0][..]), Some(&t[1][..]), Some(&t[2][..]), Some(&time[..])),
                "{r}"
            );
        }
        assert!(!out.contains("--- warning"), "{out}");
        insta::assert_snapshot!("netbsd_wtmp", out);
    }

    #[test]
    fn a_real_netbsd_lastlog_equals_the_libc_dump() {
        let out = run(&LASTLOG, "var/log/lastlog", &fixture("bsd-lastlog/netbsd-lastlog"), 0);
        let (recs, truth) = (records(&out), truth("bsd-lastlog/netbsd-lastlog.truth"));
        assert_eq!(recs.len(), truth.len(), "{out}");
        for (r, t) in recs.iter().zip(&truth) {
            let host = t.get(3).map_or("", String::as_str);
            assert_eq!(r["uid"].as_u64(), t[0].parse().ok());
            assert_eq!(r["time"].as_str(), Some(&iso(t[1].parse().unwrap_or_default())[..]));
            assert_eq!((r["line"].as_str(), r["remote_host"].as_str()), (Some(&t[2][..]), Some(host)));
        }
    }

    /// The first 14 records of a NetBSD 10.1 `wtmpx`, against `fread()` of the libc's `struct utmpx`
    /// (type, seconds, microseconds, name, id, line, host, pid, session).
    #[test]
    fn a_real_netbsd_wtmpx_equals_the_libc_dump() {
        let out = run(&UTMPX, "var/log/wtmpx", &fixture("netbsd-utmpx/netbsd-wtmpx"), 0);
        let (recs, truth) = (records(&out), truth("netbsd-utmpx/netbsd-wtmpx.truth"));
        assert_eq!(recs.len(), truth.len(), "{out}");
        let kinds = [(1, "run_level"), (2, "boot"), (7, "login"), (8, "logout"), (11, "shutdown")];
        for (r, t) in recs.iter().zip(&truth) {
            let kind = kinds.iter().find(|(n, _)| t[0].parse() == Ok(*n)).map(|(_, k)| *k);
            let micros: i64 = t[2].parse().unwrap_or_default();
            let time = iso(t[1].parse().unwrap_or_default()).replace('Z', &format!(".{micros:06}Z"));
            assert_eq!(
                (
                    r["type"].as_str(),
                    r["time"].as_str(),
                    r["user"].as_str(),
                    r["line"].as_str(),
                    r["remote_host"].as_str()
                ),
                (kind, Some(&time[..]), Some(&t[3][..]), Some(&t[5][..]), Some(&t[6][..])),
                "{r}"
            );
        }
        insta::assert_snapshot!("netbsd_wtmpx", out);
    }

    /// One OpenBSD `struct utmp`: line[8], name[32], host[256], 64-bit time.
    fn openbsd(line: &str, name: &str, host: &str, time: i64, big: bool) -> Vec<u8> {
        let mut r = vec![0u8; 304];
        r[..line.len()].copy_from_slice(line.as_bytes());
        r[8..8 + name.len()].copy_from_slice(name.as_bytes());
        r[40..40 + host.len()].copy_from_slice(host.as_bytes());
        r[296..304].copy_from_slice(&if big { time.to_be_bytes() } else { time.to_le_bytes() });
        r
    }

    /// One NetBSD `struct utmp`: line[8], name[8], host[16], 64-bit time.
    fn netbsd(line: &str, name: &str, host: &str, time: i64) -> Vec<u8> {
        let mut r = vec![0u8; 40];
        r[..line.len()].copy_from_slice(line.as_bytes());
        r[8..8 + name.len()].copy_from_slice(name.as_bytes());
        r[16..16 + host.len()].copy_from_slice(host.as_bytes());
        r[32..40].copy_from_slice(&time.to_le_bytes());
        r
    }

    #[test]
    fn openbsd_wtmp_logins_logouts_and_system_events() {
        let mut wtmp = Vec::new();
        for r in [
            openbsd("~", "reboot", "", 1_700_000_000, false),
            openbsd("ttyp0", "alice", "198.51.100.7", 1_700_000_100, false),
            openbsd("ttyp0", "", "", 1_700_000_200, false),
            openbsd("|", "|", "", 1_700_000_300, false),
            openbsd("{", "{", "", 1_700_000_310, false),
            openbsd("~", "shutdown", "", 1_700_000_400, false),
        ] {
            wtmp.extend(r);
        }
        let out = run(&UTMP, "var/log/wtmp", &wtmp, 0);
        insta::assert_snapshot!(out);
        for kind in ["boot", "login", "logout", "old_time", "new_time", "shutdown"] {
            assert!(out.contains(&format!("\"type\":\"{kind}\"")), "{kind} missing in {out}");
        }
    }

    #[test]
    fn big_endian_openbsd_and_netbsd_layouts_are_told_apart() {
        let big = openbsd("ttyp1", "bob", "h", 1_700_000_100, true);
        let out = run(&UTMP, "var/log/wtmp", &big, 0);
        assert!(out.contains("\"time\":\"2023-11-14T22:15:00Z\",\"type\":\"login\",\"user\":\"bob\""), "{out}");
        let mut net = Vec::new();
        net.extend(netbsd("ttyp0", "carol", "example", 1_700_000_100));
        net.extend(netbsd("ttyp0", "", "", 1_700_000_160));
        let out = run(&UTMP, "var/log/wtmp", &net, 0);
        assert!(out.contains("\"user\":\"carol\",\"line\":\"ttyp0\",\"remote_host\":\"example\""), "{out}");
        assert!(out.contains("\"type\":\"logout\""));
    }

    /// One NetBSD `struct utmpx` (520 bytes), little-endian.
    fn netbsd_x(kind: u16, name: &str, line: &str, host: &str, secs: i64, micros: i32, pid: u32) -> Vec<u8> {
        let mut r = vec![0u8; 520];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r[36..36 + line.len()].copy_from_slice(line.as_bytes());
        r[68..68 + host.len()].copy_from_slice(host.as_bytes());
        r[326..328].copy_from_slice(&kind.to_le_bytes());
        r[328..332].copy_from_slice(&pid.to_le_bytes());
        r[464..472].copy_from_slice(&secs.to_le_bytes());
        r[472..476].copy_from_slice(&micros.to_le_bytes());
        r
    }

    #[test]
    fn netbsd_utmpx_records() {
        let mut data = Vec::new();
        for r in [
            netbsd_x(2, "", "boot", "system boot", 1_700_000_000, 8800, 0),
            netbsd_x(7, "root", "constty", "", 1_700_000_100, 415_824, 4581),
            netbsd_x(8, "mallory", "pts/0", "127.0.0.1", 1_700_000_200, 65_049, 1982),
            netbsd_x(11, "", "down", "system down", 1_700_000_300, 0, 0),
            netbsd_x(0, "", "", "", 0, 0, 0),
        ] {
            data.extend(r);
        }
        let out = run(&UTMPX, "var/log/wtmpx", &data, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(
            "\"time\":\"2023-11-14T22:15:00.415824Z\",\"type\":\"login\",\"user\":\"root\",\"line\":\"constty\""
        ));
        assert_eq!(out.lines().take_while(|l| l.starts_with('{')).count(), 4);
    }

    #[test]
    fn lastlog_is_indexed_by_uid() {
        let mut lastlog = vec![0u8; 272 * 3];
        lastlog[272..280].copy_from_slice(&1_700_000_100i64.to_le_bytes());
        lastlog[280..285].copy_from_slice(b"ttyp0");
        lastlog[288..288 + 7].copy_from_slice(b"example");
        let passwd = b"root:*:0:0::0:0:r:/root:/bin/sh\nalice:*:1:1::0:0:a:/home/a:/bin/sh\n";
        let out = crate::testing::run_on_host(
            &LASTLOG,
            &[("var/log/lastlog", &lastlog), ("etc/passwd", passwd)],
            "var/log/lastlog",
            0,
        );
        assert!(out.contains("\"uid\":1,\"user\":\"alice\",\"time\":\"2023-11-14T22:15:00Z\",\"line\":\"ttyp0\",\"remote_host\":\"example\""), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 1);
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        let mut data = Vec::new();
        for r in
            [openbsd("~", "reboot", "", 1_700_000_000, false), openbsd("ttyp0", "alice", "h", 1_700_000_100, false)]
        {
            data.extend(r);
        }
        for artifact in [&UTMP, &LASTLOG, &UTMPX] {
            for name in ["bsd-utmp/netbsd-wtmp", "netbsd-utmpx/netbsd-wtmpx"] {
                let real = fixture(name);
                for len in (0..real.len()).step_by(9) {
                    run(artifact, "var/log/wtmp", &real[..len], 0);
                }
                for i in (0..real.len()).step_by(13) {
                    let mut flipped = real.clone();
                    flipped[i] ^= 0xff;
                    run(artifact, "var/log/wtmp", &flipped, 0);
                }
            }
            for len in (0..data.len()).step_by(7) {
                run(artifact, "var/log/wtmp", &data[..len], 0);
            }
            for i in (0..data.len()).step_by(5) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(artifact, "var/log/wtmp", &flipped, 0);
            }
        }
    }
}

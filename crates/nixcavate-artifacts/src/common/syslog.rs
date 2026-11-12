//! The header of one syslog line, shared by every syslog-family text log (Linux `syslog`,
//! `auth.log`, macOS `system.log`). Three layouts are recognised:
//!
//! 1. classic BSD, RFC 3164: `Mar  9 01:02:03 web01 sshd[1234]: message` (no year, no zone);
//! 2. ISO 8601 / RFC 3339, as written by rsyslog's high-precision format:
//!    `2024-03-10T01:02:03.123456+01:00 web01 sshd[1234]: message`;
//! 3. RFC 5424: `<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG`, where `-` means absent.
//!
//! A line that matches none of them (a continuation line, garbage) gets an empty header and the
//! whole line as its message, so no data is dropped.

use crate::text::{for_each_line, lossy};
use crate::Input;
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Result, Timestamp};
use std::borrow::Cow;

/// The longest message copied into a timeline entry.
const TIMELINE_MESSAGE_CHARS: usize = 300;

pub struct Header<'a> {
    pub time: Option<Timestamp>,
    pub log_host: Cow<'a, str>,
    pub program: Cow<'a, str>,
    pub pid: Option<u32>,
    pub message: Cow<'a, str>,
}

/// Calls `f` with the byte offset and parsed header of every non-empty line.
pub fn for_each_header(input: &Input, mut f: impl FnMut(u64, Header) -> Result<()>) -> Result<()> {
    for_each_line(input, |line| {
        if line.bytes.is_empty() {
            return Ok(());
        }
        f(line.offset, parse_header(input, line.bytes))
    })
}

/// The timeline text of a plain log line: `program: message`, with a long message cut.
pub fn timeline_message(program: &str, message: &str) -> String {
    // A message of at most 300 bytes has at most 300 chars; only long ones need the walk.
    let message = if message.len() <= TIMELINE_MESSAGE_CHARS {
        message
    } else {
        &message[..message.char_indices().nth(TIMELINE_MESSAGE_CHARS).map_or(message.len(), |(i, _)| i)]
    };
    if program.is_empty() {
        message.to_string()
    } else {
        format!("{program}: {message}")
    }
}

pub fn parse_header<'a>(input: &Input, line: &'a [u8]) -> Header<'a> {
    let parsed = match line.first() {
        Some(b'<') => rfc5424(input, line),
        Some(b) if b.is_ascii_digit() => iso(input, line),
        Some(_) => classic(input, line),
        None => None,
    };
    parsed.unwrap_or_else(|| Header {
        time: None,
        log_host: Cow::Borrowed(""),
        program: Cow::Borrowed(""),
        pid: None,
        message: lossy(line),
    })
}

fn classic<'a>(input: &Input, b: &'a [u8]) -> Option<Header<'a>> {
    if b.len() < 16 || b[3] != b' ' || b[6] != b' ' || b[9] != b':' || b[12] != b':' || b[15] != b' ' {
        return None;
    }
    let month = month_from_abbrev(&b[..3])?;
    // The day is space-padded to two columns.
    let day = if b[4] == b' ' { digit(b[5])? } else { digit(b[4])? * 10 + digit(b[5])? };
    let (h, m, s) =
        (digit(b[7])? * 10 + digit(b[8])?, digit(b[10])? * 10 + digit(b[11])?, digit(b[13])? * 10 + digit(b[14])?);
    // An impossible date (or no file mtime to infer the year from) leaves the time empty but
    // still yields the header.
    let time = crate::common::year::utc_without_year(month, day, h, m, s, input.mtime, &input.host.tz)
        .map(|utc| Timestamp::from_secs(utc, Basis::InferredYearAssumedZone));
    Some(host_and_tag(time, &b[16..]))
}

fn digit(b: u8) -> Option<u32> {
    b.is_ascii_digit().then(|| u32::from(b - b'0'))
}

fn iso<'a>(input: &Input, b: &'a [u8]) -> Option<Header<'a>> {
    let (parsed, used) = parse_iso8601(b)?;
    if b.get(used) != Some(&b' ') {
        return None;
    }
    Some(host_and_tag(Some(iso_time(input, &parsed)), &b[used + 1..]))
}

fn iso_time(input: &Input, parsed: &nixcavate_core::time::ParsedTime) -> Timestamp {
    parsed.recorded().unwrap_or_else(|| input.local_time(parsed.secs, parsed.nanos, parsed.precision))
}

/// `HOST TAG: MESSAGE`, where TAG is `program` or `program[pid]`. Without a tag (`HOST last
/// message repeated 2 times`) the whole remainder is the message. busybox syslogd writes
/// `HOST facility.level TAG: MESSAGE`; that `auth.info` word is skipped.
fn host_and_tag<'a>(time: Option<Timestamp>, rest: &'a [u8]) -> Header<'a> {
    let (host, mut after) = split_space(rest);
    let (first, tail) = split_space(after);
    if is_facility_level(first) {
        after = tail;
    }
    let (token, message) = split_space(after);
    let tag = token.strip_suffix(b":").filter(|t| !t.is_empty());
    let (program, pid, message) = match tag {
        Some(tag) => {
            let (program, pid) = split_pid(tag);
            (program, pid, message)
        }
        None => (&b""[..], None, after),
    };
    Header { time, log_host: lossy(host), program: lossy(program), pid, message: lossy(message) }
}

/// `auth.info`, `local3.err`: a known facility, a dot and a known level.
fn is_facility_level(token: &[u8]) -> bool {
    const FACILITIES: [&str; 16] = [
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp",
        "security", "console", "audit",
    ];
    const LEVELS: [&str; 10] = ["emerg", "alert", "crit", "err", "error", "warn", "warning", "notice", "info", "debug"];
    let Some(dot) = memchr::memchr(b'.', token) else { return false };
    let (facility, level) = (&token[..dot], &token[dot + 1..]);
    let local = facility.strip_prefix(b"local").is_some_and(|n| matches!(n, [b'0'..=b'7']));
    (local || FACILITIES.iter().any(|f| f.as_bytes() == facility)) && LEVELS.iter().any(|l| l.as_bytes() == level)
}

/// `name[123]` into the name and the pid; a bracket that is not a number is dropped.
fn split_pid(tag: &[u8]) -> (&[u8], Option<u32>) {
    match (memchr::memchr(b'[', tag), tag.strip_suffix(b"]")) {
        (Some(open), Some(inner)) => (&tag[..open], parse_uint(&inner[open + 1..]).and_then(|p| u32::try_from(p).ok())),
        _ => (tag, None),
    }
}

fn split_space(s: &[u8]) -> (&[u8], &[u8]) {
    match memchr::memchr(b' ', s) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &[]),
    }
}

/// An RFC 5424 field: `-` stands for absent.
fn field(bytes: &[u8]) -> &[u8] {
    if bytes == b"-" {
        &[]
    } else {
        bytes
    }
}

fn rfc5424<'a>(input: &Input, b: &'a [u8]) -> Option<Header<'a>> {
    let close = memchr::memchr(b'>', b.get(..6)?)?;
    parse_uint(&b[1..close])?;
    let mut rest = b[close + 1..].strip_prefix(b"1 ")?;
    let mut next = || {
        let (token, after) = split_space(rest);
        rest = after;
        token
    };
    let stamp = next();
    let (host, app, procid, _msgid) = (next(), next(), next(), next());
    let time = match field(stamp) {
        [] => None,
        text => {
            let (parsed, used) = parse_iso8601(text)?;
            (used == text.len()).then(|| iso_time(input, &parsed))
        }
    };
    let message = structured_data_end(rest)?;
    let message = message.strip_prefix(b" ").unwrap_or(message);
    let message = message.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(message);
    Some(Header {
        time,
        log_host: lossy(field(host)),
        program: lossy(field(app)),
        pid: parse_uint(procid).and_then(|p| u32::try_from(p).ok()),
        message: lossy(message),
    })
}

/// The bytes after the structured data: `-`, or one or more `[...]` elements in which `\]`,
/// `\"` and `\\` are escapes.
fn structured_data_end(s: &[u8]) -> Option<&[u8]> {
    if let Some(rest) = s.strip_prefix(b"-") {
        return Some(rest);
    }
    let mut pos = 0;
    while s.get(pos) == Some(&b'[') {
        pos += 1;
        loop {
            match s.get(pos)? {
                b'\\' => pos += 2,
                b']' => break,
                _ => pos += 1,
            }
        }
        pos += 1;
    }
    (pos > 0).then(|| &s[pos..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::with_input;

    const MAR_10_2024: i64 = 1_710_028_800;

    fn header(line: &[u8]) -> (Option<String>, String, String, Option<u32>, String) {
        with_input("var/log/syslog", b"x", MAR_10_2024, |input| {
            let h = parse_header(input, line);
            (h.time.map(|t| t.to_rfc3339()), h.log_host.into(), h.program.into(), h.pid, h.message.into())
        })
    }

    #[test]
    fn classic_with_and_without_pid() {
        let (t, host, program, pid, msg) = header(b"Mar  9 01:02:03 web01 sshd[1234]: Accepted x");
        assert_eq!(
            (t.as_deref(), &*host, &*program, pid, &*msg),
            (Some("2024-03-09T01:02:03Z"), "web01", "sshd", Some(1234), "Accepted x")
        );
        let (_, _, program, pid, msg) = header(b"Mar 10 01:02:03 web01 kernel: [ 1.0] up");
        assert_eq!((&*program, pid, &*msg), ("kernel", None, "[ 1.0] up"));
    }

    #[test]
    fn busybox_facility_and_level_are_skipped() {
        let (_, host, program, pid, msg) = header(
            b"Mar  9 01:02:03 alpine auth.info sshd[99]: Accepted password for alice from 203.0.113.9 port 50000 ssh2",
        );
        assert_eq!((&*host, &*program, pid), ("alpine", "sshd", Some(99)));
        assert!(msg.starts_with("Accepted password for alice"), "{msg}");
        // Not a facility.level pair: stays the message of an untagged line.
        let (_, _, program, _, msg) = header(b"Mar  9 01:02:03 web01 example.com is down");
        assert_eq!((&*program, &*msg), ("", "example.com is down"));
    }

    #[test]
    fn untagged_and_garbage_lines_keep_their_text() {
        let (t, host, program, _, msg) = header(b"Mar  9 01:02:03 web01 last message repeated 3 times");
        assert!(t.is_some());
        assert_eq!((&*host, &*program, &*msg), ("web01", "", "last message repeated 3 times"));
        let (t, host, _, _, msg) = header(b"\tcontinuation");
        assert_eq!((t, &*host, &*msg), (None, "", "\tcontinuation"));
        for line in [&b"Mar"[..], b"<", b"<13>1 ", b"<13>1 2024-03-10T01:02:03Z h a p m [", b"2024-03-10T", b"\xff\xfe"]
        {
            header(line);
        }
    }
}

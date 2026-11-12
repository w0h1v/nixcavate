//! `/var/log/install.log`: Installer, PackageKit and softwareupdated activity. Lines look like
//! `2024-03-10 01:02:03-08 host process[pid]: message`; the zone is written as hours only
//! (`-08`) or, on some versions, with minutes (`+05:30`), so the time is a recorded instant.
//! There is no published specification; the layout was taken from the file itself.
//!
//! A line without a leading timestamp (wrapped message, script output) is a continuation: it is
//! kept with `time` empty. Only lines that mark an install or removal reach the timeline; the
//! rest of this log is progress chatter, tens of thousands of lines per install.

use crate::common::syslog::timeline_message;
use crate::text::lossy;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "install-log",
    "macOS software installation log",
    Category::Software,
    MACOS,
    &["private/var/log/install.log*"],
    parse,
)
.split_lines();

/// A program tag longer than this is taken to be message text, not a process name.
const MAX_TAG: usize = 64;

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    log_host: Cow<'a, str>,
    program: Cow<'a, str>,
    pid: Option<u32>,
    message: Cow<'a, str>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .filter(|_| marks_install(&self.program, &self.message))
            .map(|ts| Event::new(ts, "software_install", timeline_message(&self.program, &self.message)))
            .into_iter()
    }
}

/// Install outcomes and removals, picked from the message texts that occur in real logs:
/// `Installed "Name" (1.0)` from installd/system_installd, `Install Succeeded`/`Install Failed`
/// from Installer, and "Installed"/`Removing "` from softwareupdated. Client bookkeeping
/// (`Removing client ...`) and script chatter are deliberately left out.
fn marks_install(program: &str, message: &str) -> bool {
    if program == "softwareupdated" && (message.starts_with("Installed ") || message.starts_with("Removing \"")) {
        return true;
    }
    message.contains("Install")
        && (message.contains("Installed \"")
            || message.contains("PackageKit: Installed")
            || message.contains("Install Succeeded")
            || message.contains("Install Failed")
            || message.contains("SUAppStoreUpdateController: Installed"))
}

/// `YYYY-MM-DD HH:MM:SS+HH[:MM]` and the number of bytes it spans.
fn timestamp(b: &[u8]) -> Option<(Timestamp, usize)> {
    let two = |at: usize| -> Option<u32> {
        let (a, c) = (*b.get(at)?, *b.get(at + 1)?);
        (a.is_ascii_digit() && c.is_ascii_digit()).then(|| u32::from(a - b'0') * 10 + u32::from(c - b'0'))
    };
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || b.get(10) != Some(&b' ') {
        return None;
    }
    if b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return None;
    }
    let year = parse_uint(b.get(..4)?)?;
    let wall = secs_from_civil(year as i64, two(5)?, two(8)?, two(11)?, two(14)?, two(17)?)?;
    let sign = match b.get(19)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hours, mut used) = (two(20)?, 22);
    let minutes = if b.get(used) == Some(&b':') {
        used += 1;
        let m = two(used)?;
        used += 2;
        m
    } else if let Some(m) = two(used) {
        used += 2;
        m
    } else {
        0
    };
    if hours > 14 || minutes > 59 {
        return None;
    }
    let offset = sign * (i64::from(hours) * 3600 + i64::from(minutes) * 60);
    Some((Timestamp::checked(wall - offset, 0, Precision::Seconds, Basis::Recorded)?, used))
}

/// `program[pid]: message` where the program may contain spaces (`Installer Progress[57]`).
fn split_tag(rest: &[u8]) -> (&[u8], Option<u32>, &[u8]) {
    let limit = rest.len().min(MAX_TAG + 1);
    let mut from = 0;
    while let Some(i) = memchr::memchr(b':', &rest[from..limit]) {
        let colon = from + i;
        if matches!(rest.get(colon + 1), None | Some(b' ')) {
            let tag = &rest[..colon];
            let message = rest.get(colon + 2..).unwrap_or(&[]);
            if let Some(inner) = tag.strip_suffix(b"]") {
                if let Some(open) = memchr::memchr(b'[', inner) {
                    if let Some(pid) = parse_uint(&inner[open + 1..]) {
                        return (&tag[..open], u32::try_from(pid).ok(), message);
                    }
                }
            }
            return (tag, None, message);
        }
        from = colon + 1;
    }
    (&[], None, rest)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    crate::text::for_each_line(input, |line| {
        if line.bytes.is_empty() {
            return Ok(());
        }
        let entry = match timestamp(line.bytes).and_then(|(time, used)| {
            let rest = line.bytes.get(used..)?.strip_prefix(b" ")?;
            let split = memchr::memchr(b' ', rest).unwrap_or(rest.len());
            Some((time, &rest[..split], rest.get(split + 1..).unwrap_or(&[])))
        }) {
            Some((time, host, rest)) => {
                let (program, pid, message) = split_tag(rest);
                Entry { time: Some(time), log_host: lossy(host), program: lossy(program), pid, message: lossy(message) }
            }
            None => Entry {
                time: None,
                log_host: Cow::Borrowed(""),
                program: Cow::Borrowed(""),
                pid: None,
                message: lossy(line.bytes),
            },
        };
        sink.emit(Loc::Offset(line.offset), &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use std::io::Write;

    const PATH: &str = "private/var/log/install.log";

    #[test]
    fn installer_lines_and_continuations() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("install-log/install.log"), 0));
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("install-log/install.log");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let from_gz = run(&ARTIFACT, "private/var/log/install.log.0.gz", &gz.finish().unwrap(), 0);
        assert_eq!(from_gz.replace("install.log.0.gz", "install.log"), run(&ARTIFACT, PATH, &plain, 0));
        assert!(from_gz.contains("software_install"));
    }

    #[test]
    fn zones_with_and_without_minutes() {
        let (t, used) = timestamp(b"2024-03-10 01:02:03-08 h").unwrap();
        assert_eq!((t.to_rfc3339().as_str(), used), ("2024-03-10T09:02:03Z", 22));
        let (t, used) = timestamp(b"2024-03-10 01:02:03+05:30 h").unwrap();
        assert_eq!((t.to_rfc3339().as_str(), used), ("2024-03-09T19:32:03Z", 25));
        let (t, _) = timestamp(b"2024-03-10 01:02:03+0530 h").unwrap();
        assert_eq!(t.to_rfc3339(), "2024-03-09T19:32:03Z");
        assert!(timestamp(b"2024-03-10 01:02:03 h").is_none());
        assert!(timestamp(b"2024-13-10 01:02:03-08 h").is_none());
        // Zones are at most +-14:00 and the minutes below 60; years past 2262 do not fit.
        for bad in ["+15 h", "-99 h", "+05:60 h", "+0575 h", "+14:59 h"] {
            let line = format!("2024-03-10 01:02:03{bad}");
            assert_eq!(timestamp(line.as_bytes()).is_some(), bad == "+14:59 h", "{bad}");
        }
        assert!(timestamp(b"9999-03-10 01:02:03+00 h").is_none());
    }

    #[test]
    fn empty_file() {
        assert_eq!(run(&ARTIFACT, PATH, b"", 0), "");
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        let data = fixture("install-log/install.log");
        for len in 0..data.len() {
            run(&ARTIFACT, PATH, &data[..len], 0);
        }
        for i in (0..data.len()).step_by(3) {
            let mut flipped = data.clone();
            flipped[i] ^= 0x5a;
            run(&ARTIFACT, PATH, &flipped, 0);
        }
    }
}

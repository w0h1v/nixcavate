//! Logs of the tools that change what is installed or how it is configured, each a line log
//! that starts every entry with a date and time:
//!
//! - `unattended-upgrades.log`: unattended-upgrade(8), Python logging `2024-03-10 01:02:03,123 INFO ...`;
//! - `dnf.log`, `dnf.librepo.log`, `hawkey.log`: dnf(8) debug logs `2024-03-10T01:02:03+0000 INFO ...`
//!   (`dnf.rpm.log` and `dnf5.log` are the package action logs, read by `dnf-log`);
//! - `zypper.log`: libzypp `2024-03-10 01:02:03 <1> host(123) [zypper] main.cc(main):142 ...`.
//!
//! `alternatives.log` and `zypp/history` have artifacts of their own (`alternatives`, `zypp`).
//!
//! A time without a zone is the host's local time and is marked as an assumed zone.

use crate::common::stamped_log::{parse, timestamp, Parsed};
use crate::common::year::utc_without_year;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Timestamp};

pub const UNATTENDED_UPGRADES: Artifact = Artifact::new(
    "unattended-upgrades-log",
    "Unattended upgrade runs",
    Category::Software,
    LINUX,
    &["var/log/unattended-upgrades/unattended-upgrades.log*"],
    |input, sink| parse(input, sink, "an unattended-upgrades log", "unattended_upgrade", level_line),
);

pub const DNF_DEBUG: Artifact = Artifact::new(
    "dnf-debug-log",
    "dnf debug, librepo and hawkey logs",
    Category::Software,
    LINUX,
    &["var/log/dnf.log*", "var/log/dnf.librepo.log*", "var/log/hawkey.log*"],
    |input, sink| parse(input, sink, "a dnf debug log", "dnf", level_line),
);

pub const ZYPPER: Artifact = Artifact::new(
    "zypper-log",
    "zypper and libzypp log",
    Category::Software,
    LINUX,
    &["var/log/zypper.log*"],
    |input, sink| parse(input, sink, "a zypper.log", "zypper", zypper_line),
);

/// `INFO Nov-30 21:31:45 message`: `hawkey.log` as libdnf wrote it before 0.48 (RHEL 8.0 to
/// 8.2). The line has no year and no zone: the year is inferred from the file's time.
fn old_hawkey_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (level, rest) = line.split_once(' ')?;
    if level.is_empty() || !level.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let stamp = rest.as_bytes();
    let month = month_from_abbrev(stamp)?;
    let number = |range: std::ops::Range<usize>| parse_uint(stamp.get(range)?).and_then(|n| u32::try_from(n).ok());
    let separators = [stamp.get(3), stamp.get(6), stamp.get(9), stamp.get(12)]
        == [Some(&b'-'), Some(&b' '), Some(&b':'), Some(&b':')];
    let (day, hour, minute, second) = (number(4..6)?, number(7..9)?, number(10..12)?, number(13..15)?);
    separators.then_some(())?;
    let time = utc_without_year(month, day, hour, minute, second, input.mtime, &input.host.tz)
        .map(|secs| Timestamp::from_secs(secs, Basis::InferredYearAssumedZone));
    Some(Parsed {
        time,
        level: Some(level),
        source: None,
        pid: None,
        message: rest.get(15..).unwrap_or_default().trim_start(),
        timeline: !matches!(level, "DEBUG" | "DDEBUG" | "TRACE"),
    })
}

/// `2024-03-10 01:02:03,123 INFO message` and `2024-03-10T01:02:03+0000 INFO message`.
fn level_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    if let Some(parsed) = old_hawkey_line(input, line) {
        return Some(parsed);
    }
    let (time, used) = parse_iso8601(line.as_bytes())?;
    let rest = line.get(used..)?.strip_prefix(' ')?;
    let (level, message) = rest.split_once(' ').unwrap_or((rest, ""));
    // A line that merely starts with a date has no level word: keep it whole.
    let is_level = !level.is_empty() && level.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let (level, message) = if is_level { (Some(level), message) } else { (None, rest) };
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level,
        source: None,
        pid: None,
        message,
        timeline: !matches!(level, Some("DEBUG" | "DDEBUG" | "TRACE")),
    })
}

/// libzypp's log levels (`<n>`): debug, milestone, warning, error, security, internal, user.
fn zypper_level(number: u64) -> Option<&'static str> {
    ["debug", "milestone", "warning", "error", "security", "internal", "user"].get(number as usize).copied()
}

/// `2024-03-10 01:02:03 <1> host(123) [zypper] main.cc(main):142 message`
fn zypper_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (time, used) = parse_iso8601(line.as_bytes())?;
    let rest = line.get(used..)?.strip_prefix(" <")?;
    let (level, rest) = rest.split_once("> ")?;
    let level = parse_uint(level.as_bytes())?;
    let (origin, rest) = rest.split_once(' ')?;
    let pid = origin
        .rsplit_once('(')
        .and_then(|(_, p)| parse_uint(p.strip_suffix(')')?.as_bytes()))
        .and_then(|p| u32::try_from(p).ok());
    let (component, message) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((component, message)) => (Some(component), message),
        None => (None, rest),
    };
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: zypper_level(level),
        source: component,
        pid,
        message,
        // Warnings and worse, and the line that records the command being run.
        timeline: (2..=4).contains(&level) || message.contains("===== '"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> usize {
        out.lines().take_while(|l| !l.starts_with("---")).count()
    }

    fn non_blank_lines(data: &[u8]) -> usize {
        data.split(|&b| b == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)).count()
    }

    /// Every non-blank line is a record and nothing warns.
    fn check(artifact: &Artifact, path: &str, name: &str) -> String {
        let data = fixture(name);
        let out = run(artifact, path, &data, 0);
        assert_eq!(records(&out), non_blank_lines(&data), "{name}");
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        out
    }

    #[test]
    fn unattended_upgrades_log_times_and_levels() {
        let out = check(
            &UNATTENDED_UPGRADES,
            "var/log/unattended-upgrades/unattended-upgrades.log",
            "applogs/unattended-upgrades/unattended-upgrades.log",
        );
        assert!(out.contains("\"time\":\"2026-11-12T22:58:29.145Z\",\"level\":\"INFO\""), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn dnf_debug_logs_carry_a_zone() {
        for name in ["dnf.log", "dnf.librepo.log", "hawkey.log"] {
            let out = check(&DNF_DEBUG, &format!("var/log/{name}"), &format!("applogs/dnf/{name}"));
            assert!(out.contains("\"time\":\"2026-11-12T22:5"), "{out}");
        }
        insta::assert_snapshot!(check(&DNF_DEBUG, "var/log/dnf.log", "applogs/dnf/dnf.log"));
    }

    /// libdnf before 0.48 (RHEL 8.0 to 8.2) wrote `hawkey.log` with the level first and no
    /// year: the year comes from the file's time, as for classic syslog.
    #[test]
    fn old_hawkey_lines_have_the_level_first_and_no_year() {
        let log = b"INFO Nov-30 21:31:45 === Started libdnf-0.35.1 ===\nDEBUG Nov-30 21:31:46 fetching rpmdb\n";
        // 2019-12-01T00:00:00Z as the file's time.
        let out = run(&DNF_DEBUG, "var/log/hawkey.log", log, 1_575_158_400);
        assert!(!out.contains("failed") && !out.contains("warning"), "{out}");
        assert!(out.contains(r#""time":"2019-11-30T21:31:45Z""#) && out.contains(r#""level":"INFO""#), "{out}");
        assert!(out.contains(r#""message":"=== Started libdnf-0.35.1 ===""#), "{out}");
    }

    #[test]
    fn debug_lines_are_not_timeline_events() {
        let out = run(
            &UNATTENDED_UPGRADES,
            "var/log/unattended-upgrades/unattended-upgrades.log",
            b"2024-03-10 01:02:03,123 DEBUG noisy\n2024-03-10 01:02:04,000 INFO kept\n",
            0,
        );
        assert_eq!(out.matches("unattended_upgrade").count(), 1, "{out}");
    }

    #[test]
    fn zypper_log() {
        let out = check(&ZYPPER, "var/log/zypper.log", "applogs/zypper/zypper.log");
        assert!(out.contains("\"level\":\"milestone\",\"source\":\"zypper\",\"pid\":11"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn continuation_lines_are_kept_without_a_time() {
        let out = run(
            &UNATTENDED_UPGRADES,
            "var/log/unattended-upgrades/unattended-upgrades.log",
            b"2024-03-10 01:02:03,123 ERROR boom\nTraceback (most recent call last):\n  File \"x\"\n\n",
            0,
        );
        assert_eq!(out.matches("\"time\":null").count(), 2, "{out}");
    }

    #[test]
    fn other_files_and_empty_files_are_refused() {
        let path = "var/log/zypper.log";
        assert!(run(&ZYPPER, path, b"just some text\n2024-03-10 01:02:03 x\n", 0).contains("not a zypper.log"));
        assert!(run(&ZYPPER, path, b"", 0).contains("skipped"));
    }

    #[test]
    fn hostile_lines_never_panic() {
        let cases: [&[u8]; 9] = [
            b"2024-03-10 01:02:03,123",
            b"2024-03-10 01:02:03,123 ",
            b"2024-13-45 99:99:99 <9> x",
            b"2024-03-10 01:02:03 <",
            b"2024-03-10 01:02:03 <99999999999999999999> a(1) [b] c",
            b"update-alternatives 2024-03-10 01:02:03",
            b"update-alternatives",
            b"|||||",
            b"\xff\xfe 2024-03-10\n",
        ];
        for data in cases {
            for artifact in [&UNATTENDED_UPGRADES, &DNF_DEBUG, &ZYPPER] {
                run(artifact, "var/log/x", data, 0);
            }
        }
        let full = fixture("applogs/zypper/zypper.log");
        for cut in (0..full.len().min(4000)).step_by(13) {
            run(&ZYPPER, "var/log/zypper.log", &full[..cut], 0);
        }
    }
}

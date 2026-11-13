//! `/var/log/dmesg*`: a saved copy of the kernel ring buffer (written at boot by older
//! distributions, or by `dmesg > file`). Format reference: dmesg(1), in the forms it prints:
//!
//! - `[    7.581400] text`: seconds since boot, the default;
//! - `[Thu Nov 12 22:33:20 2026] text`: `-T`, a wall-clock time with no zone;
//! - `kern  :info  : [    7.581400] text`: `-x`, facility and level first;
//! - `<6>[    7.581400] text`: `-r`, the raw priority.
//!
//! Seconds since boot are kept as such: turning them into a clock time needs the boot time,
//! which the file does not hold, so only the `-T` form gets a timestamp.

use crate::common::syslog::timeline_message;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{month_from_abbrev, parse_uint, secs_from_civil};
use nixcavate_core::{Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("dmesg", "Saved kernel ring buffer (dmesg)", Category::Logs, LINUX, &["var/log/dmesg*"], parse);

#[derive(Serialize)]
struct Message<'a> {
    /// Only when the line carries a wall-clock time (`dmesg -T`).
    time: Option<Timestamp>,
    /// Seconds since boot, as printed.
    monotonic_seconds: Option<f64>,
    facility: Option<&'a str>,
    level: Option<&'a str>,
    message: &'a str,
}

impl Record for Message<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|t| Event::new(t, "kernel_message", timeline_message("kernel", self.message))).into_iter()
    }
}

/// Syslog facility names for the numbers `dmesg -r` prints (priority / 8).
fn facility_name(number: u32) -> Option<&'static str> {
    const NAMES: [&str; 12] =
        ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp"];
    const LOCAL: [&str; 8] = ["local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"];
    match number {
        0..=11 => NAMES.get(number as usize).copied(),
        16..=23 => LOCAL.get(number as usize - 16).copied(),
        _ => None,
    }
}

fn level_name(number: u32) -> Option<&'static str> {
    ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"].get(number as usize).copied()
}

/// What sits inside the brackets: seconds since boot, or `Thu Nov 12 22:33:20 2026`.
enum Stamp {
    Boot(f64),
    Wall(i64),
}

fn stamp(inside: &str) -> Option<Stamp> {
    let inside = inside.trim();
    if !inside.is_empty() && inside.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return inside.parse().ok().map(Stamp::Boot);
    }
    // weekday month day time year, with the day padded by a space for single digits.
    let mut words = inside.split_whitespace();
    let (_weekday, month, day, time, year) =
        (words.next()?, words.next()?, words.next()?, words.next()?, words.next()?);
    if words.next().is_some() {
        return None;
    }
    let mut clock = time.split(':');
    let (h, m, s) = (clock.next()?, clock.next()?, clock.next()?);
    let number = |text: &str| parse_uint(text.as_bytes()).and_then(|v| u32::try_from(v).ok());
    let secs = secs_from_civil(
        number(year)?.into(),
        month_from_abbrev(month.as_bytes())?,
        number(day)?,
        number(h)?,
        number(m)?,
        number(s)?,
    )?;
    Some(Stamp::Wall(secs))
}

/// Splits the `facility :level : ` prefix of `dmesg -x`, which pads both names with blanks.
fn decoded_prefix(line: &str) -> Option<(&str, &str, &str)> {
    let (facility, rest) = line.split_once(':')?;
    let (level, rest) = rest.split_once(':')?;
    let word = |w: &str| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase());
    let (facility, level) = (facility.trim_end(), level.trim_end());
    (word(facility) && word(level) && rest.trim_start().starts_with('[')).then_some((
        facility,
        level,
        rest.trim_start(),
    ))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen = false;
    let mut stamped = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        let mut rest: &str = &text;
        let (mut facility, mut level) = (None, None);
        if let Some(raw) = rest.strip_prefix('<') {
            if let Some((priority, after)) = raw.split_once('>') {
                if let Some(priority) = parse_uint(priority.as_bytes()).and_then(|p| u32::try_from(p).ok()) {
                    (facility, level) = (facility_name(priority >> 3), level_name(priority & 7));
                    rest = after;
                }
            }
        } else if let Some((f, l, after)) = decoded_prefix(rest) {
            (facility, level, rest) = (Some(f), Some(l), after);
        }
        let mut message = Message { time: None, monotonic_seconds: None, facility, level, message: rest };
        let bracketed = rest.strip_prefix('[').and_then(|r| r.split_once(']'));
        match bracketed.and_then(|(inside, after)| Some((stamp(inside)?, after))) {
            Some((found, after)) => {
                stamped = true;
                message.message = after.strip_prefix(' ').unwrap_or(after);
                match found {
                    Stamp::Boot(seconds) => message.monotonic_seconds = Some(seconds),
                    Stamp::Wall(secs) => message.time = Some(input.local_time(secs, 0, Precision::Seconds)),
                }
            }
            // A ring buffer file starts with a stamped line; later lines without one continue
            // the message before them and are kept as they are.
            // Ubuntu 14.04 and 16.04 leave this placeholder when no boot messages were saved.
            None if !seen && rest.trim() == "(Nothing has been logged yet.)" => {
                return Err(Error::skipped("no kernel messages were saved"))
            }
            None if !seen => {
                return Err(Error::format("not a kernel ring buffer (no `[seconds]` stamp on the first line)"))
            }
            None => {}
        }
        seen = true;
        sink.emit(Loc::Line(line.number), &message)
    })?;
    if !seen {
        return Err(Error::skipped("empty file"));
    }
    if !stamped {
        sink.warn("no line carries a timestamp");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// `dmesg`, `dmesg -T`, `dmesg -x` and `dmesg -r` of a real kernel, separated by `===`.
    fn form(n: usize) -> Vec<u8> {
        let all = String::from_utf8(fixture("applogs/dmesg/all.txt")).unwrap();
        all.split("===\n").nth(n).unwrap().as_bytes().to_vec()
    }

    /// Ubuntu 14.04 and 16.04 keep this one line in `/var/log/dmesg` when nothing was saved.
    #[test]
    fn the_nothing_logged_placeholder_is_skipped_not_failed() {
        let out = run(&ARTIFACT, "var/log/dmesg", b"(Nothing has been logged yet.)\n", 0);
        assert!(out.contains("skipped") && !out.contains("failed"), "{out}");
    }

    #[test]
    fn default_form_has_seconds_since_boot_only() {
        let out = run(&ARTIFACT, "var/log/dmesg", &form(0), 0);
        assert!(out.contains("\"time\":null,\"monotonic_seconds\":1450665.381918"), "{out}");
        assert!(!out.contains("--- timeline"), "no clock time, no events: {out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn wall_clock_form_is_timed_in_the_assumed_zone() {
        let out = run(&ARTIFACT, "var/log/dmesg.0", &form(1), 0);
        assert!(out.contains("\"time\":\"2026-11-12T22:33:24Z\"") && out.contains("--- timeline"), "{out}");
        assert!(out.contains("\"monotonic_seconds\":null"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn decoded_and_raw_forms_keep_facility_and_level() {
        let out = run(&ARTIFACT, "var/log/dmesg", &form(2), 0);
        assert!(out.contains("\"facility\":\"kern\",\"level\":\"info\""), "{out}");
        let out = run(&ARTIFACT, "var/log/dmesg", &form(3), 0);
        assert!(out.contains("\"facility\":\"kern\",\"level\":\"info\""), "{out}");
    }

    #[test]
    fn every_line_is_a_record() {
        for n in 0..4 {
            let data = form(n);
            let lines = data.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count();
            let out = run(&ARTIFACT, "var/log/dmesg", &data, 0);
            assert_eq!(out.matches("\"artifact\":\"dmesg\"").count(), lines, "form {n}");
        }
    }

    #[test]
    fn continuation_lines_and_other_text() {
        let out = run(&ARTIFACT, "var/log/dmesg", b"[    0.000000] first\n  continued\n\n[    1.5] second\n", 0);
        assert_eq!(out.matches("\"artifact\":\"dmesg\"").count(), 3, "{out}");
        assert!(out.contains("\"monotonic_seconds\":null,\"facility\":null,\"level\":null,\"message\":\"  continued\""));
        let out = run(&ARTIFACT, "var/log/dmesg", b"hello\n[    0.0] x\n", 0);
        assert!(out.contains("failed: ") && out.contains("not a kernel ring buffer"), "{out}");
        assert!(run(&ARTIFACT, "var/log/dmesg", b"", 0).contains("skipped"));
    }

    #[test]
    fn hostile_stamps_never_panic() {
        for data in [
            &b"[inf] x\n"[..],
            b"[1e5] x\n",
            b"[ . ] x\n",
            b"[Thu Nov 99 99:99:99 99999999999] x\n",
            b"[Thu Nov 12 22:33 2026] x\n",
            b"<>[1.0] x\n",
            b"<99999999999999999999>[1.0] x\n",
            b"<8>[1.0] x\n<191>[1.0] y\n",
            b":: [1.0] x\n",
            b"kern :info: [1.0\n",
            b"[",
            b"]",
            b"\xff\xfe[1.0] \xff\n",
        ] {
            run(&ARTIFACT, "var/log/dmesg", data, 0);
        }
        let full = form(1);
        for cut in (0..full.len()).step_by(7) {
            run(&ARTIFACT, "var/log/dmesg", &full[..cut], 0);
        }
    }
}

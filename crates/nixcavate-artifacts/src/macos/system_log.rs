//! `/var/log/system.log` and its rotations: the BSD syslog text log that syslogd wrote before
//! the Unified Log. Layout: see `common::syslog`. Records and events have the same shape as the
//! Linux `syslog` artifact so the two can be analysed together.
//!
//! `--- last message repeated N times ---` and tab-indented continuation lines carry no header,
//! so they come out as message-only records, as on Linux. `wifi.log` is not listed: it mixes
//! several layouts and is not syslog format.

use crate::common::syslog::{for_each_header, timeline_message};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "macos-system-log",
    "macOS syslog text log (system.log and rotations)",
    Category::Logs,
    MACOS,
    &["private/var/log/system.log*"],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    log_host: &'a str,
    program: &'a str,
    pid: Option<u32>,
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "log", timeline_message(self.program, self.message))).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_header(input, |offset, h| {
        let entry = Entry {
            time: h.time,
            time_basis: h.time.map(|t| t.basis),
            log_host: &h.log_host,
            program: &h.program,
            pid: h.pid,
            message: &h.message,
        };
        sink.emit(Loc::Offset(offset), &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use std::io::Write;

    const NOV_11_2026: i64 = 1_794_355_200;
    const PATH: &str = "private/var/log/system.log";

    #[test]
    fn classic_lines_with_repeats_and_continuations() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("macos-system-log/system.log"), NOV_11_2026));
    }

    #[test]
    fn without_mtime_there_is_no_time() {
        let out = run(&ARTIFACT, PATH, &fixture("macos-system-log/system.log"), 0);
        assert!(!out.contains("--- timeline ---") && out.contains("\"time\":null"));
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("macos-system-log/system.log");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let from_gz = run(&ARTIFACT, "private/var/log/system.log.0.gz", &gz.finish().unwrap(), NOV_11_2026);
        assert_eq!(from_gz.replace("system.log.0.gz", "system.log"), run(&ARTIFACT, PATH, &plain, NOV_11_2026));
        assert!(from_gz.contains("syslogd"));
    }

    #[test]
    fn empty_file() {
        assert_eq!(run(&ARTIFACT, PATH, b"", NOV_11_2026), "");
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        let data = fixture("macos-system-log/system.log");
        for len in 0..data.len() {
            run(&ARTIFACT, PATH, &data[..len], NOV_11_2026);
        }
        for i in (0..data.len()).step_by(3) {
            let mut flipped = data.clone();
            flipped[i] ^= 0x5a;
            run(&ARTIFACT, PATH, &flipped, NOV_11_2026);
        }
    }
}

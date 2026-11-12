//! Debian package state: `/var/lib/dpkg/status` (the package database, format deb-control(5))
//! and `/var/log/dpkg.log` (the action log, format dpkg(1) `--log`).

use crate::text::{decompressed, for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use memchr::memchr;
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const STATUS: Artifact = Artifact::new(
    "dpkg-status",
    "Debian package database",
    Category::Software,
    LINUX,
    &["var/lib/dpkg/status", "var/lib/dpkg/status-old"],
    parse_status,
);

pub const LOG: Artifact = Artifact::new(
    "dpkg-log",
    "Debian package actions (dpkg.log)",
    Category::Software,
    LINUX,
    &["var/log/dpkg.log*"],
    parse_log,
)
.split_lines();

/// Seconds since the epoch of a host-local `YYYY-MM-DD` date and `HH:MM:SS` time, no zone applied.
pub(super) fn wall_secs(date: &[u8], time: &[u8]) -> Option<i64> {
    let field = |b: &[u8], from: usize, to: usize| -> Option<u32> { parse_uint(b.get(from..to)?).map(|v| v as u32) };
    if date.len() != 10 || time.len() != 8 || date[4] != b'-' || date[7] != b'-' || time[2] != b':' || time[5] != b':' {
        return None;
    }
    secs_from_civil(
        field(date, 0, 4)?.into(),
        field(date, 5, 7)?,
        field(date, 8, 10)?,
        field(time, 0, 2)?,
        field(time, 3, 5)?,
        field(time, 6, 8)?,
    )
}

// ---- dpkg-status ----

#[derive(Serialize, Default)]
struct Package<'a> {
    package: Cow<'a, str>,
    version: Cow<'a, str>,
    architecture: Cow<'a, str>,
    /// The whole Status field: want, flag and state, e.g. `install ok installed`.
    status: Cow<'a, str>,
    /// False for removed packages whose configuration files remain (`config-files`) and the like.
    installed: bool,
    installed_size_kb: Option<u64>,
    section: Cow<'a, str>,
    priority: Cow<'a, str>,
    maintainer: Cow<'a, str>,
    source_package: Cow<'a, str>,
    /// First line of the Description.
    summary: Cow<'a, str>,
}

impl Record for Package<'_> {}

fn parse_status(input: &Input, sink: &mut Sink) -> Result<()> {
    // Stanzas span lines and borrow from the buffer, so work on the whole decompressed file.
    let data = decompressed(input.data)?;
    let (mut start, mut number) = (0, 0u64);
    let mut stanza: Option<(u64, Package)> = None;
    while start < data.len() {
        let end = memchr(b'\n', &data[start..]).map_or(data.len(), |i| start + i);
        let mut line = &data[start..end];
        start = end + 1;
        number += 1;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            if let Some((at, package)) = stanza.take() {
                emit_package(sink, at, package)?;
            }
            continue;
        }
        // Continuation lines belong to a multi-line field; only the first Description line is kept.
        if line[0] == b' ' || line[0] == b'\t' {
            continue;
        }
        let Some(colon) = memchr(b':', line) else {
            sink.warn(format!("line {number}: not a `Field: value` line"));
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        let (_, package) = stanza.get_or_insert_with(|| (number, Package::default()));
        let slot = match name.len() {
            7 if name.eq_ignore_ascii_case(b"Package") => &mut package.package,
            7 if name.eq_ignore_ascii_case(b"Version") => &mut package.version,
            6 if name.eq_ignore_ascii_case(b"Status") => &mut package.status,
            6 if name.eq_ignore_ascii_case(b"Source") => &mut package.source_package,
            7 if name.eq_ignore_ascii_case(b"Section") => &mut package.section,
            8 if name.eq_ignore_ascii_case(b"Priority") => &mut package.priority,
            10 if name.eq_ignore_ascii_case(b"Maintainer") => &mut package.maintainer,
            12 if name.eq_ignore_ascii_case(b"Architecture") => &mut package.architecture,
            11 if name.eq_ignore_ascii_case(b"Description") => &mut package.summary,
            14 if name.eq_ignore_ascii_case(b"Installed-Size") => {
                package.installed_size_kb = parse_uint(value);
                continue;
            }
            _ => continue,
        };
        *slot = lossy(value);
    }
    if let Some((at, package)) = stanza {
        emit_package(sink, at, package)?;
    }
    Ok(())
}

fn emit_package(sink: &mut Sink, at: u64, mut package: Package) -> Result<()> {
    if package.package.is_empty() {
        sink.warn(format!("line {at}: stanza without a Package field"));
        return Ok(());
    }
    package.installed = package.status.ends_with(" installed");
    sink.emit(Loc::Line(at), &package)
}

// ---- dpkg-log ----

#[derive(Serialize)]
struct Action<'a> {
    time: Timestamp,
    /// `install`, `upgrade`, `remove`, `purge`, `configure`, `trigproc`, `status`, `startup`, `conffile`.
    action: &'a str,
    /// The package state, for `status` lines.
    state: &'a str,
    package: &'a str,
    architecture: &'a str,
    old_version: &'a str,
    /// For `status` lines, the package's version at that state.
    new_version: &'a str,
    /// `startup`: the log phase and command; `conffile`: the path and the decision taken.
    detail: &'a str,
}

impl Record for Action<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, verb, version) = match self.action {
            "install" => ("package_installed", "installed", self.new_version),
            "upgrade" => ("package_upgraded", "upgraded", self.new_version),
            "remove" => ("package_removed", "removed", self.old_version),
            "purge" => ("package_removed", "purged", self.old_version),
            _ => return None.into_iter(),
        };
        let mut message = format!("{verb} {} ", self.package);
        if self.action == "upgrade" {
            message.push_str(&format!("{} -> ", self.old_version));
        }
        message.push_str(version);
        if !self.architecture.is_empty() {
            message.push_str(&format!(" ({})", self.architecture));
        }
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

/// `<none>` is dpkg's marker for "no such version".
fn version(text: &str) -> &str {
    if text == "<none>" {
        ""
    } else {
        text
    }
}

fn parse_log(input: &Input, sink: &mut Sink) -> Result<()> {
    // Zone conversion costs more than the rest of the line, and neighbours share a second.
    let mut last = (i64::MIN, input.local_time(0, 0, Precision::Seconds));
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let text = lossy(line.bytes);
        let mut words = text.splitn(4, ' ');
        let (date, time, action) = (words.next().unwrap_or(""), words.next().unwrap_or(""), words.next());
        let (Some(secs), Some(action)) = (wall_secs(date.as_bytes(), time.as_bytes()), action) else {
            sink.warn(format!("offset {}: not a dpkg.log line", line.offset));
            return Ok(());
        };
        let rest = words.next().unwrap_or("");
        let mut action = Action {
            time: {
                if last.0 != secs {
                    last = (secs, input.local_time(secs, 0, Precision::Seconds));
                }
                last.1
            },
            action,
            state: "",
            package: "",
            architecture: "",
            old_version: "",
            new_version: "",
            detail: "",
        };
        let mut fields = rest.split(' ');
        match action.action {
            "startup" | "conffile" => action.detail = rest,
            "status" => {
                action.state = fields.next().unwrap_or("");
                set_package(&mut action, fields.next().unwrap_or(""));
                action.new_version = version(fields.next().unwrap_or(""));
            }
            _ => {
                set_package(&mut action, fields.next().unwrap_or(""));
                action.old_version = version(fields.next().unwrap_or(""));
                action.new_version = version(fields.next().unwrap_or(""));
            }
        }
        sink.emit(Loc::Offset(line.offset), &action)
    })
}

fn set_package<'a>(action: &mut Action<'a>, name: &'a str) {
    (action.package, action.architecture) = name.split_once(':').unwrap_or((name, ""));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(data).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn status_database() {
        insta::assert_snapshot!(run(&STATUS, "var/lib/dpkg/status", &fixture("dpkg-status/status"), 0));
    }

    #[test]
    fn status_edge_cases_warn() {
        let data = b"Package: a\nStatus: install ok installed\n\nVersion: 1\nGarbage line\n\n\n";
        insta::assert_snapshot!(run(&STATUS, "var/lib/dpkg/status-old", data, 0));
    }

    #[test]
    fn status_without_trailing_newline_and_with_crlf() {
        let out = run(&STATUS, "var/lib/dpkg/status", b"Package: a\r\nStatus: install ok installed\r\nVersion: 1", 0);
        assert!(out.contains(r#""package":"a","version":"1""#) && out.contains(r#""installed":true"#), "{out}");
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(run(&STATUS, "var/lib/dpkg/status", b"", 0), "");
        assert_eq!(run(&LOG, "var/log/dpkg.log", b"", 0), "");
    }

    #[test]
    fn log_entries() {
        insta::assert_snapshot!(run(&LOG, "var/log/dpkg.log", &fixture("dpkg-log/dpkg.log"), 0));
    }

    #[test]
    fn log_actions_and_malformed_lines() {
        insta::assert_snapshot!(run(&LOG, "var/log/dpkg.log", &fixture("dpkg-log/extra.log"), 0));
    }

    #[test]
    fn rotated_log_is_decompressed() {
        let plain = fixture("dpkg-log/extra.log");
        let rotated = run(&LOG, "var/log/dpkg.log.2.gz", &gzip(&plain), 0);
        // Offsets are those of the decompressed text, so only the paths differ.
        assert_eq!(rotated.replace("dpkg.log.2.gz", "dpkg.log"), run(&LOG, "var/log/dpkg.log", &plain, 0));
    }

    #[test]
    fn log_time_uses_the_host_zone() {
        let files: &[(&str, &[u8])] = &[
            ("var/log/dpkg.log", b"2024-03-10 01:02:03 install nmap:amd64 <none> 7.93\n2024-07-01 12:00:00 remove nmap:amd64 7.93 <none>\n"),
            ("etc/localtime", &fixture("dpkg-log/Europe_Berlin.tzif")),
        ];
        let out = run_on_host(&LOG, files, "var/log/dpkg.log", 0);
        // Berlin is UTC+1 in March and UTC+2 in July.
        assert!(out.contains("2024-03-10T00:02:03Z") && out.contains("2024-07-01T10:00:00Z"), "{out}");
        assert!(out.contains("assumed_zone"), "{out}");
    }

    #[test]
    fn never_panics_on_damaged_input() {
        for (artifact, name) in [(&STATUS, "dpkg-status/status"), (&LOG, "dpkg-log/dpkg.log")] {
            let data = fixture(name);
            for len in (0..data.len()).step_by(7) {
                run(artifact, "var/lib/dpkg/status", &data[..len], 0);
            }
            let mut seed = 0x2545_f491_4f6c_dd1du64;
            for _ in 0..200 {
                let mut copy = data.clone();
                for _ in 0..8 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, "var/lib/dpkg/status", &copy, 0);
            }
        }
    }
}

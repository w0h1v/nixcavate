//! Arch Linux package state: `/var/log/pacman.log` (the action log, written by libalpm and
//! pacman) and the local database `/var/lib/pacman/local/<name>-<version>/desc` (one small
//! `%KEY%` / value file per installed package; format: libalpm's `alpm-db-desc(5)`).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use memchr::memchr;
use nixcavate_core::time::{parse_iso8601, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Pattern;
use serde::Serialize;
use std::borrow::Cow;

pub const LOG: Artifact = Artifact::new(
    "pacman-log",
    "Arch pacman actions (pacman.log)",
    Category::Software,
    LINUX,
    &["var/log/pacman.log*"],
    parse_log,
)
.split_lines();

/// One task for the whole database. A task per `desc` file would be a task (and an output
/// file) per package, over a thousand on a desktop; the one file every local database has,
/// `ALPM_DB_VERSION`, stands in for the directory and the parser walks the packages itself.
pub const DB: Artifact = Artifact::new(
    "pacman-db",
    "Arch installed packages (pacman local database)",
    Category::Software,
    LINUX,
    &["var/lib/pacman/local/ALPM_DB_VERSION"],
    parse_db,
);

/// Seconds since the epoch of a host-local `YYYY-MM-DD HH:MM` wall time, no zone applied.
/// Shared with the other logs that omit the seconds (xbps).
pub(super) fn minute_secs(text: &[u8]) -> Option<i64> {
    let field = |from: usize, to: usize| -> Option<u32> { parse_uint(text.get(from..to)?).map(|v| v as u32) };
    if text.len() < 16 || text[4] != b'-' || text[7] != b'-' || !matches!(text[10], b' ' | b'T') || text[13] != b':' {
        return None;
    }
    secs_from_civil(field(0, 4)?.into(), field(5, 7)?, field(8, 10)?, field(11, 13)?, field(14, 16)?, 0)
}

// ---- pacman-log ----

#[derive(Serialize)]
struct Entry<'a> {
    time: Timestamp,
    time_basis: Basis,
    /// `ALPM` (the library), `PACMAN` (the command), `ALPM-SCRIPTLET` (output of a package script).
    source: &'a str,
    /// `installed`, `upgraded`, `downgraded`, `reinstalled` or `removed` for a package action.
    action: &'a str,
    package: &'a str,
    /// The version installed (for `removed`, the version that was removed).
    version: &'a str,
    /// The version replaced, for `upgraded` and `downgraded`.
    old_version: &'a str,
    /// The command line, for the `Running '...'` lines.
    command: &'a str,
    /// Everything else: transaction markers, hook runs, script output, warnings.
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, verb) = match self.action {
            "installed" => ("package_installed", "installed"),
            "upgraded" => ("package_upgraded", "upgraded"),
            "removed" => ("package_removed", "removed"),
            "downgraded" => ("package_changed", "downgraded"),
            "reinstalled" => ("package_changed", "reinstalled"),
            _ if !self.command.is_empty() => {
                return Some(Event::new(self.time, "package_command", self.command)).into_iter()
            }
            _ => return None.into_iter(),
        };
        let message = if self.old_version.is_empty() {
            format!("{verb} {} {}", self.package, self.version)
        } else {
            format!("{verb} {} {} -> {}", self.package, self.old_version, self.version)
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

/// `[2024-03-10T01:02:03+0000] ` (zone written) or `[2019-01-02 03:04] ` (older pacman: local
/// time, no seconds, no zone). Returns the time, its basis and the text after the bracket.
fn stamp<'a>(input: &Input, line: &'a [u8], cache: &mut (i64, Timestamp)) -> Option<(Timestamp, &'a [u8])> {
    let inner = line.strip_prefix(b"[")?;
    let close = memchr(b']', inner)?;
    let (text, rest) = (&inner[..close], inner[close + 1..].trim_ascii_start());
    if let Some((parsed, _)) = parse_iso8601(text).filter(|(_, used)| *used == text.len()) {
        return Some((parsed.recorded().unwrap_or_else(|| input.local_time(parsed.secs, 0, Precision::Seconds)), rest));
    }
    let secs = minute_secs(text).filter(|_| text.len() == 16)?;
    if cache.0 != secs {
        *cache = (secs, input.local_time(secs, 0, Precision::Seconds));
    }
    Some((cache.1, rest))
}

/// `foo (1.2-3)` or `foo (1.0 -> 1.1)`: the package, its version and the version it replaced.
fn package_version(text: &str) -> Option<(&str, &str, &str)> {
    let (package, tail) = text.split_once(" (")?;
    let versions = tail.strip_suffix(')')?;
    Some(match versions.split_once(" -> ") {
        Some((old, new)) => (package, new, old),
        None => (package, versions, ""),
    })
}

fn parse_log(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut cache = (i64::MIN, input.local_time(0, 0, Precision::Seconds));
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let Some((time, rest)) = stamp(input, line.bytes, &mut cache) else {
            sink.warn(format!("offset {}: not a pacman.log line", line.offset));
            return Ok(());
        };
        let text = lossy(rest);
        // `[SOURCE] text`; before pacman 4 there was no source tag.
        let (source, body) = match text.strip_prefix('[').and_then(|t| t.split_once("] ")) {
            Some((source, body)) => (source, body),
            None => ("", &*text),
        };
        let mut entry = Entry {
            time,
            time_basis: time.basis,
            source,
            action: "",
            package: "",
            version: "",
            old_version: "",
            command: "",
            message: body,
        };
        if let Some((word, tail)) = body.split_once(' ') {
            let action = ["installed", "upgraded", "downgraded", "reinstalled", "removed"].iter().find(|a| **a == word);
            if let (Some(action), true) = (action, source != "ALPM-SCRIPTLET") {
                if let Some((package, version, old)) = package_version(tail) {
                    (entry.action, entry.package, entry.version, entry.old_version) = (action, package, version, old);
                    entry.message = "";
                }
            } else if source == "PACMAN" || source.is_empty() {
                if let Some(command) = word.eq("Running").then(|| tail.strip_prefix('\'')?.strip_suffix('\'')).flatten()
                {
                    entry.command = command;
                    entry.message = "";
                }
            }
        }
        sink.emit(Loc::Offset(line.offset), &entry)
    })
}

// ---- pacman-db ----

#[derive(Serialize, Default)]
struct Package<'a> {
    /// The install time. libalpm rewrites it when a package is upgraded or reinstalled.
    time: Option<Timestamp>,
    package: Cow<'a, str>,
    version: Cow<'a, str>,
    architecture: Cow<'a, str>,
    /// `explicit` (asked for) or `dependency` (pulled in by another package).
    install_reason: &'static str,
    build_time: Option<Timestamp>,
    size_bytes: Option<u64>,
    packager: Cow<'a, str>,
    url: Cow<'a, str>,
    license: String,
    description: Cow<'a, str>,
    /// How the package file was verified: `pgp`, `sha256`, `md5`, `none`.
    validation: String,
    /// Where the record was read, relative to the host root.
    package_path: String,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("installed {} {}", self.package, self.version);
        self.time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

/// A `desc` file larger than this is not a package description.
const MAX_DESC: u64 = 1 << 20;
/// Multi-line fields (`%LICENSE%`, `%VALIDATION%`) are joined and cut at this length.
const MAX_JOINED: usize = 1024;

fn join(into: &mut String, line: &str) {
    if into.len() < MAX_JOINED {
        if !into.is_empty() {
            into.push(' ');
        }
        into.push_str(line);
    }
}

/// Parses one `desc`: `%KEY%` on a line of its own, then the value lines, then a blank line.
fn parse_desc<'a>(data: &'a [u8], path: &str) -> Option<Package<'a>> {
    let mut package = Package { install_reason: "explicit", package_path: path.to_string(), ..Package::default() };
    let mut key: &[u8] = b"";
    let mut seen_value = false;
    for line in data.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            key = b"";
            continue;
        }
        if line.len() > 2 && line[0] == b'%' && line[line.len() - 1] == b'%' {
            key = &line[1..line.len() - 1];
            continue;
        }
        let value = lossy(line);
        let number = || parse_uint(line);
        let time = || {
            number()
                .and_then(|secs| Timestamp::checked(i64::try_from(secs).ok()?, 0, Precision::Seconds, Basis::Recorded))
        };
        seen_value = true;
        match key {
            b"NAME" => package.package = value,
            b"VERSION" => package.version = value,
            b"ARCH" => package.architecture = value,
            b"DESC" => package.description = value,
            b"URL" => package.url = value,
            b"PACKAGER" => package.packager = value,
            b"INSTALLDATE" => package.time = time(),
            b"BUILDDATE" => package.build_time = time(),
            b"SIZE" => package.size_bytes = number(),
            b"REASON" => package.install_reason = if number() == Some(0) { "explicit" } else { "dependency" },
            b"LICENSE" => join(&mut package.license, &value),
            b"VALIDATION" => join(&mut package.validation, &value),
            _ => {}
        }
    }
    (seen_value && !package.package.is_empty()).then_some(package)
}

fn parse_db(input: &Input, sink: &mut Sink) -> Result<()> {
    let descs = Pattern::new("var/lib/pacman/local/*/desc");
    for entry in input.host.find(&descs).filter(|e| e.link.is_none()) {
        let path = input.host.rel(entry);
        if entry.size > MAX_DESC {
            sink.warn(format!("{path}: larger than {} KiB, not read", MAX_DESC >> 10));
            continue;
        }
        let data = match input.host.open(entry) {
            Ok(data) => data,
            Err(e) => {
                sink.warn(format!("{path}: cannot read: {e}"));
                continue;
            }
        };
        match parse_desc(&data, &path) {
            Some(package) => sink.emit(Loc::None, &package)?,
            None => sink.warn(format!("{path}: no package name")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn parses_a_real_log() {
        insta::assert_snapshot!(run(&LOG, "var/log/pacman.log", &fixture("pacman-log/pacman.log"), 0));
    }

    #[test]
    fn upgrades_downgrades_and_the_old_local_time_form() {
        let log = concat!(
            "[2019-01-02 03:04] [PACMAN] Running 'pacman -Syu'\n",
            "[2019-01-02 03:04] [ALPM] upgraded linux (5.0.1-1 -> 5.0.2-1)\n",
            "[2019-01-02 03:05] [ALPM] downgraded foo (2.0-1 -> 1.9-1)\n",
            "[2019-01-02 03:05] [ALPM] reinstalled bar (1.0-1)\n",
            "[2019-01-02 03:05] [ALPM-SCRIPTLET] installed (this is script output)\n",
            "[2019-01-02 03:06] [ALPM] warning: /etc/foo installed as /etc/foo.pacnew\n",
            "[2019-01-02 03:06] installed legacy (0.1-1)\n",
            "[2019-01-02 03:06] not a [ALPM] line either\n",
            "garbage\n",
        );
        insta::assert_snapshot!(run(&LOG, "var/log/pacman.log", log.as_bytes(), 0));
    }

    #[test]
    fn empty_log_produces_nothing() {
        assert_eq!(run(&LOG, "var/log/pacman.log", b"", 0), "");
    }

    #[test]
    fn local_time_uses_the_host_zone() {
        let out = run(&LOG, "var/log/pacman.log", b"[2019-01-02 03:04] [ALPM] installed foo (1-1)\n", 0);
        // No zone data on the test host: UTC is assumed, and the record says so.
        assert!(out.contains("\"time\":\"2019-01-02T03:04:00Z\",\"time_basis\":\"assumed_zone\""), "{out}");
    }

    const DESCS: [&str; 3] = ["jq-1.8.2-1", "oniguruma-6.9.10-3", "tree-2.3.2-1"];

    fn db_files() -> Vec<(String, Vec<u8>)> {
        let mut files = vec![("var/lib/pacman/local/ALPM_DB_VERSION".to_string(), b"9\n".to_vec())];
        for dir in DESCS {
            files.push((format!("var/lib/pacman/local/{dir}/desc"), fixture(&format!("pacman-db/{dir}/desc"))));
        }
        files
    }

    #[test]
    fn reads_the_local_database() {
        let files = db_files();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        insta::assert_snapshot!(run_on_host(&DB, &refs, "var/lib/pacman/local/ALPM_DB_VERSION", 0));
    }

    #[test]
    fn a_damaged_desc_is_a_warning_and_the_rest_is_read() {
        let mut files = db_files();
        files.push(("var/lib/pacman/local/broken-1-1/desc".to_string(), b"%NAME%\n\n%VERSION%\n\x00\xff\n".to_vec()));
        files.push(("var/lib/pacman/local/empty-1-1/desc".to_string(), b"x".to_vec()));
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        let out = run_on_host(&DB, &refs, "var/lib/pacman/local/ALPM_DB_VERSION", 0);
        assert_eq!(out.matches("\"package\":").count(), 3, "{out}");
        assert_eq!(out.matches("no package name").count(), 2, "{out}");
    }

    #[test]
    fn desc_fields_survive_mutation() {
        let desc = fixture("pacman-db/tree-2.3.2-1/desc");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for len in 0..desc.len() {
            let _ = parse_desc(&desc[..len], "p");
        }
        for _ in 0..3000 {
            let mut copy = desc.clone();
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = parse_desc(&copy, "p");
        }
    }
}

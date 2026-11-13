//! Gentoo package state: `/var/log/emerge.log` (portage's action log) and the installed-package
//! database `/var/db/pkg/<category>/<name>-<version>/` (the "vdb": one directory of small
//! files per package; only the descriptive ones are read).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Pattern;
use serde::Serialize;
use std::borrow::Cow;

pub const LOG: Artifact = Artifact::new(
    "emerge-log",
    "Gentoo emerge actions",
    Category::Software,
    LINUX,
    &["var/log/emerge.log*"],
    parse_log,
)
.split_lines();

/// Files that exist once on every host with a portage database, in the order they are
/// preferred. The vdb has a directory per package, which would be one task (and one output
/// file) per package, ten thousand on a full system; one of these stands in for the whole
/// database and the parser walks the packages itself. `emerge.log` is the last resort: it
/// is there on any host that has run emerge.
const ANCHORS: [&str; 3] = ["var/cache/edb/counter", "var/lib/portage/world", "var/log/emerge.log"];

pub const DB: Artifact = Artifact::new(
    "portage-db",
    "Gentoo installed packages (portage database)",
    Category::Software,
    LINUX,
    &["var/cache/edb/counter", "var/lib/portage/world", "var/log/emerge.log"],
    parse_db,
);

// ---- emerge-log ----

#[derive(Serialize)]
struct Entry<'a> {
    time: Timestamp,
    /// `installed` (`::: completed emerge`), `removed` (`>>> unmerge success`), `merge_started`
    /// (`>>> emerge`), `command` (`*** emerge ...`); empty for any other line.
    action: &'static str,
    /// `category/name-version`.
    package: &'a str,
    /// `3 of 20`: this package's place in the transaction.
    position: &'a str,
    command: &'a str,
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let event = match self.action {
            "installed" => Event::new(self.time, "package_installed", format!("installed {}", self.package)),
            "removed" => Event::new(self.time, "package_removed", format!("removed {}", self.package)),
            "command" => Event::new(self.time, "package_command", format!("emerge {}", self.command)),
            _ => return None.into_iter(),
        };
        Some(event).into_iter()
    }
}

/// `(3 of 20) cat/pkg-1.0 to /` after the marker: the position and the package.
fn position_and_package(text: &str) -> (&str, &str) {
    let Some((position, rest)) = text.strip_prefix('(').and_then(|t| t.split_once(") ")) else { return ("", "") };
    let package = rest.split_once(" to ").map_or(rest, |(package, _)| package);
    (position, package.trim())
}

/// `1710032523:  >>> emerge (1 of 3) dev-libs/foo-1.2 to /`: the epoch, a colon, then the event.
fn parse_log(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let stamp = line.bytes.iter().position(|b| *b == b':').and_then(|at| {
            let secs = parse_uint(&line.bytes[..at])?;
            let time = Timestamp::checked(i64::try_from(secs).ok()?, 0, Precision::Seconds, Basis::Recorded)?;
            Some((time, &line.bytes[at + 1..]))
        });
        let Some((time, rest)) = stamp else {
            sink.warn(format!("offset {}: not an emerge.log line", line.offset));
            return Ok(());
        };
        let text = lossy(rest);
        let body = text.trim();
        let mut entry = Entry { time, action: "", package: "", position: "", command: "", message: body };
        if let Some(tail) = body.strip_prefix(">>> emerge ") {
            (entry.position, entry.package) = position_and_package(tail);
            entry.action = "merge_started";
            entry.message = "";
        } else if let Some(tail) = body.strip_prefix("::: completed emerge ") {
            (entry.position, entry.package) = position_and_package(tail);
            entry.action = "installed";
            entry.message = "";
        } else if let Some(package) = body.strip_prefix(">>> unmerge success: ") {
            (entry.action, entry.package, entry.message) = ("removed", package.trim(), "");
        } else if let Some(command) = body.strip_prefix("*** emerge ") {
            // `*** emerge --ask foo`: what the user typed, without the program name.
            (entry.action, entry.command, entry.message) = ("command", command, "");
        }
        sink.emit(Loc::Offset(line.offset), &entry)
    })
}

// ---- portage-db ----

#[derive(Serialize, Default)]
struct Package<'a> {
    /// When the package's database entry was last written: normally the merge. This is the
    /// file's own modification time, not something portage records.
    time: Option<Timestamp>,
    /// `category/name-version`.
    package: String,
    category: String,
    name: String,
    version: String,
    /// When the package was built. For a binary package that is long before it was installed.
    build_time: Option<Timestamp>,
    size_bytes: Option<u64>,
    slot: Cow<'a, str>,
    /// The repository the ebuild came from (`gentoo`, an overlay).
    repository: Cow<'a, str>,
    /// Portage's merge counter: orders packages by installation.
    counter: Option<u64>,
    description: Cow<'a, str>,
    license: Cow<'a, str>,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("installed {} (package database entry)", self.package);
        self.time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

/// Splits `foo-bar-1.2.3-r1` into the name and the version: the version starts at the last
/// `-` followed by a digit, after an optional `-rN` revision is set aside.
fn split_version(pf: &str) -> (&str, &str) {
    let core = match pf.rsplit_once("-r") {
        Some((core, revision)) if !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit()) => core,
        _ => pf,
    };
    let bytes = core.as_bytes();
    let split = (2..bytes.len()).rev().find(|&i| bytes[i - 1] == b'-' && bytes[i].is_ascii_digit());
    match split {
        Some(i) => (&pf[..i - 1], &pf[i..]),
        None => (pf, ""),
    }
}

/// The small files of a package directory are text of a few bytes; anything larger is not one.
const MAX_FILE: u64 = 8 << 10;

fn parse_db(input: &Input, sink: &mut Sink) -> Result<()> {
    // Only the first anchor present does the work; the others are the same database.
    let first = ANCHORS.iter().find(|a| input.host.entry(a).is_some_and(|e| e.size > 0));
    if first.is_some_and(|a| *a != input.path) {
        return Err(Error::skipped("the package database is read through another anchor file"));
    }
    let build_times = Pattern::new("var/db/pkg/*/*/BUILD_TIME");
    let mut found = false;
    for entry in input.host.find(&build_times).filter(|e| e.link.is_none()) {
        let path = input.host.rel(entry);
        let Some(dir) = path.strip_suffix("/BUILD_TIME") else { continue };
        let Some((category, pf)) = dir.strip_prefix("var/db/pkg/").and_then(|d| d.split_once('/')) else { continue };
        found = true;
        let text = |name: &str| -> Option<String> {
            let child = input.host.entry(&format!("{dir}/{name}"))?;
            if child.size > MAX_FILE {
                return None;
            }
            let data = input.host.open(child).ok()?;
            Some(String::from_utf8_lossy(&data).trim().to_string())
        };
        let number = |name: &str| text(name).and_then(|t| t.parse::<u64>().ok());
        let (name, version) = split_version(pf);
        let record = Package {
            time: (entry.mtime > 0)
                .then(|| Timestamp::checked(entry.mtime, 0, Precision::Seconds, Basis::Recorded))
                .flatten(),
            package: format!("{category}/{pf}"),
            category: category.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            build_time: number("BUILD_TIME")
                .and_then(|secs| Timestamp::checked(i64::try_from(secs).ok()?, 0, Precision::Seconds, Basis::Recorded)),
            size_bytes: number("SIZE"),
            slot: Cow::Owned(text("SLOT").unwrap_or_default()),
            repository: Cow::Owned(text("repository").unwrap_or_default()),
            counter: number("COUNTER"),
            description: Cow::Owned(text("DESCRIPTION").unwrap_or_default()),
            license: Cow::Owned(text("LICENSE").unwrap_or_default()),
        };
        sink.emit(Loc::None, &record)?;
    }
    if !found {
        return Err(Error::skipped("no packages under var/db/pkg"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn parses_a_real_emerge_log() {
        insta::assert_snapshot!(run(&LOG, "var/log/emerge.log", &fixture("emerge-log/emerge.log"), 0));
    }

    #[test]
    fn unmerges_commands_and_bad_lines() {
        let log = concat!(
            "1710032523:  >>> emerge (1 of 2) dev-libs/foo-1.2 to /\n",
            "1710032530:  ::: completed emerge (1 of 2) dev-libs/foo-1.2 to /\n",
            "1710032531:  >>> unmerge success: dev-libs/foo-1.1\n",
            "1710032540:  *** emerge --ask --unmerge bar\n",
            "1710032541:  === Unmerging... (dev-libs/bar-3)\n",
            "oops\n",
            "99999999999999999999:  nope\n",
        );
        insta::assert_snapshot!(run(&LOG, "var/log/emerge.log", log.as_bytes(), 0));
    }

    #[test]
    fn empty_log_produces_nothing() {
        assert_eq!(run(&LOG, "var/log/emerge.log", b"", 0), "");
    }

    #[test]
    fn splits_package_versions() {
        assert_eq!(split_version("tree-2.2.1"), ("tree", "2.2.1"));
        assert_eq!(split_version("bash-5.3_p20-r1"), ("bash", "5.3_p20-r1"));
        assert_eq!(split_version("gtk+-3.24.1"), ("gtk+", "3.24.1"));
        assert_eq!(split_version("foo-bar-baz-1.0-r12"), ("foo-bar-baz", "1.0-r12"));
        assert_eq!(split_version("docbook-xml-dtd-4.1.2-r7"), ("docbook-xml-dtd", "4.1.2-r7"));
        assert_eq!(split_version("manpager-1"), ("manpager", "1"));
        assert_eq!(split_version("noversion"), ("noversion", ""));
        assert_eq!(split_version("-1"), ("-1", ""));
        assert_eq!(split_version(""), ("", ""));
    }

    const PACKAGES: [&str; 3] = ["app-misc/jq-1.8.2", "app-text/tree-2.2.1", "dev-libs/oniguruma-6.9.10"];
    const FILES: [&str; 6] = ["BUILD_TIME", "SIZE", "SLOT", "repository", "COUNTER", "DESCRIPTION"];

    fn db() -> Vec<(String, Vec<u8>)> {
        let mut files = vec![("var/cache/edb/counter".to_string(), fixture("portage-db/counter"))];
        for package in PACKAGES {
            for name in FILES.iter().chain(&["LICENSE"]) {
                files.push((format!("var/db/pkg/{package}/{name}"), fixture(&format!("portage-db/{package}/{name}"))));
            }
        }
        files
    }

    #[test]
    fn reads_the_package_database_once() {
        let files = db();
        let mut refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        refs.push(("var/log/emerge.log", b"1710032523:  *** terminating.\n"));
        insta::assert_snapshot!(run_on_host(&DB, &refs, "var/cache/edb/counter", 0));
        // The same database through a lesser anchor does nothing.
        let text = run_on_host(&DB, &refs, "var/log/emerge.log", 0);
        assert!(text.contains("skipped: the package database is read through another anchor file"), "{text}");
    }

    #[test]
    fn falls_back_to_the_log_as_anchor_and_skips_an_empty_database() {
        let files: Vec<_> = db().into_iter().filter(|(p, _)| p != "var/cache/edb/counter").collect();
        let mut refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        refs.push(("var/log/emerge.log", b"1710032523:  *** terminating.\n"));
        let text = run_on_host(&DB, &refs, "var/log/emerge.log", 0);
        assert_eq!(text.matches("\"package\":").count(), 3, "{text}");
        let text = run_on_host(&DB, &[("var/cache/edb/counter", b"12\n")], "var/cache/edb/counter", 0);
        assert!(text.contains("skipped: no packages under var/db/pkg"), "{text}");
    }
}

//! Alpine package state: `/lib/apk/db/installed` (the installed-package database, one stanza
//! per package, one `X:value` line per field; format: apk-tools' `apk-v2(5)` "installed
//! database" description) and `/etc/apk/world` (the packages that were asked for by name).
//!
//! apk keeps no install log and no install time, so these records have no timeline events:
//! `build_time` is when the package was built, not when it arrived on the host.

use crate::text::{decompressed, for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use memchr::memchr;
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashSet;

pub const INSTALLED: Artifact = Artifact::new(
    "apk-installed",
    "Alpine installed packages (apk database)",
    Category::Software,
    LINUX,
    &["lib/apk/db/installed"],
    parse_installed,
)
.companions(&["etc/apk/world"]);

pub const WORLD: Artifact = Artifact::new(
    "apk-world",
    "Alpine packages installed by name (apk world)",
    Category::Software,
    LINUX,
    &["etc/apk/world"],
    parse_world,
);

/// A dependency or provides list longer than this is cut: they are free text in the file.
const MAX_LIST: usize = 4096;

#[derive(Serialize, Default)]
struct Package<'a> {
    package: Cow<'a, str>,
    version: Cow<'a, str>,
    architecture: Cow<'a, str>,
    /// Size of the `.apk` file.
    package_size_bytes: Option<u64>,
    installed_size_bytes: Option<u64>,
    description: Cow<'a, str>,
    url: Cow<'a, str>,
    license: Cow<'a, str>,
    /// The source package it was built from.
    origin: Cow<'a, str>,
    maintainer: Cow<'a, str>,
    /// When the package was built (not when it was installed).
    build_time: Option<Timestamp>,
    commit: Cow<'a, str>,
    /// The package checksum (`Q1` and base64 of a SHA-1), as apk stores it.
    checksum: Cow<'a, str>,
    depends: Cow<'a, str>,
    provides: Cow<'a, str>,
    /// Number of files the package owns (its `R:` lines); the file list itself is not output.
    file_count: u64,
    /// True when the package is named in `/etc/apk/world`; empty when that file is not there.
    explicitly_installed: Option<bool>,
}

impl Record for Package<'_> {}

/// The package name of a world entry: no tag (`@edge`) and no version constraint.
fn world_name(entry: &str) -> &str {
    let entry = entry.trim_start_matches('!');
    let end = entry.find(['<', '>', '=', '~', '@']).unwrap_or(entry.len());
    &entry[..end]
}

fn capped(value: &[u8]) -> Cow<'_, str> {
    lossy(&value[..value.len().min(MAX_LIST)])
}

fn parse_installed(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    let world: Option<HashSet<String>> = input
        .host
        .read_text("etc/apk/world")
        .map(|text| text.split_ascii_whitespace().map(|entry| world_name(entry).to_string()).collect());
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
                emit(sink, at, package, &world)?;
            }
            continue;
        }
        let (Some(&field), Some(b':')) = (line.first(), line.get(1)) else {
            sink.warn(format!("line {number}: not a `X:value` line"));
            continue;
        };
        let value = &line[2..];
        let (_, package) = stanza.get_or_insert_with(|| (number, Package::default()));
        match field {
            b'P' => package.package = lossy(value),
            b'V' => package.version = lossy(value),
            b'A' => package.architecture = lossy(value),
            b'S' => package.package_size_bytes = parse_uint(value),
            b'I' => package.installed_size_bytes = parse_uint(value),
            b'T' => package.description = capped(value),
            b'U' => package.url = capped(value),
            b'L' => package.license = capped(value),
            b'o' => package.origin = lossy(value),
            b'm' => package.maintainer = capped(value),
            b't' => {
                package.build_time = parse_uint(value).and_then(|secs| {
                    Timestamp::checked(i64::try_from(secs).ok()?, 0, Precision::Seconds, Basis::Recorded)
                })
            }
            b'c' => package.commit = lossy(value),
            b'C' => package.checksum = lossy(value),
            b'D' => package.depends = capped(value),
            b'p' => package.provides = capped(value),
            b'R' => package.file_count += 1,
            _ => {}
        }
    }
    if let Some((at, package)) = stanza {
        emit(sink, at, package, &world)?;
    }
    Ok(())
}

fn emit(sink: &mut Sink, at: u64, mut package: Package, world: &Option<HashSet<String>>) -> Result<()> {
    if package.package.is_empty() {
        sink.warn(format!("line {at}: stanza without a package name"));
        return Ok(());
    }
    package.explicitly_installed = world.as_ref().map(|names| names.contains(&*package.package));
    sink.emit(Loc::Line(at), &package)
}

#[derive(Serialize)]
struct WorldEntry<'a> {
    /// The line as written: a name, optionally `name@tag`, optionally a version constraint.
    entry: &'a str,
    package: &'a str,
    /// The part after the name (`>=1.2`, `=3.4-r0`, `~1.2`); empty for a plain name.
    constraint: &'a str,
}

impl Record for WorldEntry<'_> {}

fn parse_world(input: &Input, sink: &mut Sink) -> Result<()> {
    // `world` normally has one entry per line; apk also accepts them separated by spaces.
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        for entry in text.split_ascii_whitespace() {
            let package = world_name(entry);
            let after = entry.trim_start_matches('!').get(package.len()..).unwrap_or("");
            let constraint = after.find(['<', '>', '=', '~']).map_or("", |at| &after[at..]);
            sink.emit(Loc::Line(line.number), &WorldEntry { entry, package, constraint })?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn parses_a_real_installed_database() {
        let world = fixture("apk-installed/world");
        let out = run_on_host(
            &INSTALLED,
            &[("lib/apk/db/installed", &fixture("apk-installed/installed")), ("etc/apk/world", &world)],
            "lib/apk/db/installed",
            0,
        );
        assert_eq!(out.matches("\"package\":").count(), 19, "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn world_marks_explicit_packages_and_is_optional() {
        let db = fixture("apk-installed/installed");
        let out = run(&INSTALLED, "lib/apk/db/installed", &db, 0);
        assert!(out.contains("\"explicitly_installed\":null") && !out.contains("\"explicitly_installed\":true"));
        let world = b"tree\njq>=1.0\n!bad\nbusybox@edge=1.37\n";
        let out = run_on_host(
            &INSTALLED,
            &[("lib/apk/db/installed", &db), ("etc/apk/world", world)],
            "lib/apk/db/installed",
            0,
        );
        let explicit = out.lines().filter(|l| l.contains("\"explicitly_installed\":true")).count();
        assert_eq!(explicit, 3, "{out}");
    }

    #[test]
    fn parses_world() {
        let data = b"alpine-base\nbusybox>=1.37.0-r0\nopenssh@edge\n!conflicting\ncurl=8.0\n\n";
        insta::assert_snapshot!(run(&WORLD, "etc/apk/world", data, 0));
    }

    #[test]
    fn bad_lines_are_warnings_and_empty_input_is_nothing() {
        let out = run(&INSTALLED, "lib/apk/db/installed", b"P:a\nV:1\nnot a field\n\nV:2\n\nP:b\n", 0);
        assert_eq!(out.matches("\"package\":").count(), 2, "{out}");
        assert!(out.contains("line 3: not a `X:value` line") && out.contains("stanza without a package name"), "{out}");
        assert_eq!(run(&INSTALLED, "lib/apk/db/installed", b"", 0), "");
        assert_eq!(run(&WORLD, "etc/apk/world", b"", 0), "");
    }

    #[test]
    fn mutated_databases_never_panic() {
        let db = fixture("apk-installed/installed");
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for len in (0..db.len()).step_by(97) {
            let _ = run(&INSTALLED, "lib/apk/db/installed", &db[..len], 0);
        }
        for _ in 0..300 {
            let mut copy = db.clone();
            for _ in 0..1 + next() % 8 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = run(&INSTALLED, "lib/apk/db/installed", &copy, 0);
        }
    }
}

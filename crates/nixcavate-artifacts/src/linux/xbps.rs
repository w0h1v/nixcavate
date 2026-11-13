//! Void Linux package state: `/var/db/xbps/pkgdb-0.38.plist`, xbps's installed-package
//! database, a property list whose top-level dictionary is keyed by package name. Format:
//! xbps(7) / `xbps-pkgdb(1)` plus the keys observed in real databases (`pkgver`, `state`,
//! `install-date`, `installed_size`, `repository`, `automatic-install`, ...). The file is
//! read through the same guarded property-list reader the macOS artifacts use.

use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "xbps-pkgdb",
    "Void installed packages (xbps database)",
    Category::Software,
    LINUX,
    &["var/db/xbps/pkgdb-*.plist"],
    parse,
);

#[derive(Serialize)]
struct Package<'a> {
    /// `install-date`: xbps writes it in UTC (`2024-03-10 01:02 UTC`), to the minute.
    time: Option<Timestamp>,
    package: &'a str,
    /// The version part of `pkgver` (`2.4.0_1` in `acl-2.4.0_1`).
    version: &'a str,
    pkgver: &'a str,
    architecture: &'a str,
    /// `installed`, `unpacked`, `half-unpacked`, `half-removed`, ...
    state: &'a str,
    /// True when it was installed as a dependency, not asked for.
    automatic_install: Option<bool>,
    installed_size_bytes: Option<u64>,
    repository: &'a str,
    description: &'a str,
    maintainer: &'a str,
    license: &'a str,
    homepage: &'a str,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("installed {}", if self.pkgver.is_empty() { self.package } else { self.pkgver });
        self.time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

fn install_time(text: &str, input: &Input) -> Option<Timestamp> {
    let secs = super::pacman::minute_secs(text.as_bytes())?;
    Some(if text.get(16..).is_some_and(|zone| zone.trim() == "UTC") {
        Timestamp::from_secs(secs, Basis::Recorded)
    } else {
        // Anything but UTC is a wall time of unknown zone.
        input.local_time(secs, 0, Precision::Seconds)
    })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = nixcavate_source::plist::parse(input.data)?;
    let Some(packages) = root.as_dictionary() else {
        return Err(Error::skipped("not a dictionary of packages"));
    };
    for (name, value) in packages {
        // `_XBPS_ALTERNATIVES_` and any other bookkeeping key.
        if name.starts_with('_') {
            continue;
        }
        let Some(dict) = value.as_dictionary() else {
            sink.warn(format!("{name}: not a dictionary"));
            continue;
        };
        let string = |key: &str| dict.get(key).and_then(Value::as_string).unwrap_or("");
        let pkgver = string("pkgver");
        let version = pkgver.rsplit_once('-').map_or("", |(_, version)| version);
        let date = string("install-date");
        let time = install_time(date, input);
        if time.is_none() && !date.is_empty() {
            sink.warn(format!("{name}: install-date {date:?} is not a time; left empty"));
        }
        let record = Package {
            time,
            package: name,
            version,
            pkgver,
            architecture: string("architecture"),
            state: string("state"),
            automatic_install: dict.get("automatic-install").and_then(Value::as_boolean),
            installed_size_bytes: size(dict),
            repository: string("repository"),
            description: string("short_desc"),
            maintainer: string("maintainer"),
            license: string("license"),
            homepage: string("homepage"),
        };
        sink.emit(Loc::None, &record)?;
    }
    Ok(())
}

fn size(dict: &Dictionary) -> Option<u64> {
    dict.get("installed_size")?.as_unsigned_integer()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_a_real_database() {
        let out = run(&ARTIFACT, "var/db/xbps/pkgdb-0.38.plist", &fixture("xbps-pkgdb/pkgdb-0.38.plist"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn odd_values_are_handled() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>_XBPS_ALTERNATIVES_</key><dict><key>sh</key><array><string>dash</string></array></dict>
<key>local</key><dict><key>pkgver</key><string>local-1.0_1</string><key>install-date</key><string>2024-03-10 01:02</string>
<key>automatic-install</key><true/><key>installed_size</key><integer>-5</integer></dict>
<key>junk</key><string>text</string>
<key>baddate</key><dict><key>pkgver</key><string>baddate-2_1</string><key>install-date</key><string>yesterday</string></dict>
</dict></plist>"#;
        insta::assert_snapshot!(run(&ARTIFACT, "var/db/xbps/pkgdb-0.38.plist", plist.as_bytes(), 0));
    }

    #[test]
    fn other_files_are_skipped_or_failed_not_panicked() {
        let path = "var/db/xbps/pkgdb-0.38.plist";
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, path, b"not a plist at all", 0).contains("failed"));
        let array = br#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#;
        assert!(run(&ARTIFACT, path, array, 0).contains("skipped: not a dictionary of packages"));
        // Nesting far beyond anything real: refused before it can overflow the stack.
        let mut deep = String::from(r#"<?xml version="1.0"?><plist version="1.0">"#);
        deep.push_str(&"<array>".repeat(100_000));
        let out = run(&ARTIFACT, path, deep.as_bytes(), 0);
        assert!(out.contains("nested deeper"), "{}", &out[..out.len().min(200)]);
    }

    #[test]
    fn mutated_databases_never_panic() {
        let file = fixture("xbps-pkgdb/pkgdb-0.38.plist");
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for len in (0..file.len()).step_by(211) {
            let _ = run(&ARTIFACT, "var/db/xbps/pkgdb-0.38.plist", &file[..len], 0);
        }
        for _ in 0..200 {
            let mut copy = file.clone();
            for _ in 0..1 + next() % 6 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = run(&ARTIFACT, "var/db/xbps/pkgdb-0.38.plist", &copy, 0);
        }
    }
}

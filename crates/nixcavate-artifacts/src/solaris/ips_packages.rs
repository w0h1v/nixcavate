//! `var/pkg/state/installed/catalog.base.C`: the packages installed in an IPS image. The file is
//! JSON: `{"publisher": {"name": [{"version": "...", "metadata": {"states": [...],
//! "last-install": "20250503T092906.342281Z"}}]}}`. `last-install` is when that version was
//! installed (UTC).
//!
//! OmniOS r151060 keeps the same information in an SQLite 3 file instead, `var/pkg/state/catalog.db`: a
//! `packages` table (publisher, stem, version, `installed`, and the same JSON as `base`) that also lists
//! the packages the publishers offer; only the rows with `installed = 1` are read.
//!
//! Verified on illumos (OmniOS r151054 and r151060): 424 and 420 packages, the same names and versions as
//! `pkg list -H`, and the install time of the packages the harness added.

use super::when::ips_time;
use crate::sqlite::{open_with_tables, sql_error, text_at};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const ARTIFACT: Artifact = Artifact::new(
    "ips-packages",
    "Packages installed in an IPS image (the installed catalog)",
    Category::Software,
    SOLARIS,
    &["var/pkg/state/installed/catalog.base.C", "var/pkg/state/catalog.db"],
    parse,
);

/// The largest catalog read; real ones are under a megabyte.
const MAX_BYTES: usize = 64 << 20;

#[derive(Serialize)]
struct Package<'a> {
    publisher: &'a str,
    name: &'a str,
    /// `0.5.11,5.11-151054.0:20250502T150005Z`: version, build and the time the package was published.
    version: &'a str,
    last_install: Option<Timestamp>,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} installed ({})", self.name, self.version.split(':').next().unwrap_or(self.version));
        self.last_install.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.data.starts_with(b"SQLite format 3\0") {
        return parse_sqlite(input, sink);
    }
    if input.data.len() > MAX_BYTES {
        return Err(Error::format(format!(
            "catalog is {} MiB: larger than the {} MiB read",
            input.data.len() >> 20,
            MAX_BYTES >> 20
        )));
    }
    let value: Value =
        serde_json::from_slice(input.data).map_err(|e| Error::format(format!("not a JSON catalog: {e}")))?;
    let Some(publishers) = value.as_object() else { return Err(Error::format("the catalog is not a JSON object")) };
    // `_SIGNATURE` and `_FEATURE` are the catalog's own keys.
    for (publisher, packages) in publishers.iter().filter(|(key, _)| !key.starts_with('_')) {
        let Some(packages) = packages.as_object() else {
            sink.warn(format!("publisher {publisher}: not a list of packages"));
            continue;
        };
        for (name, versions) in packages {
            for version in versions.as_array().into_iter().flatten() {
                let Some(v) = version.get("version").and_then(Value::as_str) else {
                    sink.warn(format!("package {name}: an entry has no version"));
                    continue;
                };
                let last = version.get("metadata").and_then(|m| m.get("last-install")).and_then(Value::as_str);
                sink.emit(Loc::None, &Package { publisher, name, version: v, last_install: last.and_then(ips_time) })?;
            }
        }
    }
    Ok(())
}

/// The installed packages of `catalog.db`.
fn parse_sqlite(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["packages"])?;
    let mut statement = db
        .conn
        .prepare("SELECT pub, stem, version, base FROM packages WHERE installed = 1 ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let (publisher, name, version) = (
            text_at(row, 0).unwrap_or_default(),
            text_at(row, 1).unwrap_or_default(),
            text_at(row, 2).unwrap_or_default(),
        );
        let base = text_at(row, 3).unwrap_or_default();
        let last = serde_json::from_str::<Value>(&base)
            .ok()
            .and_then(|v| v.get("metadata")?.get("last-install")?.as_str().map(str::to_string));
        sink.emit(
            Loc::None,
            &Package {
                publisher: &publisher,
                name: &name,
                version: &version,
                last_install: last.as_deref().and_then(ips_time),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// The catalog is cut to eight packages; `pkg list -H` of the image printed the same names and versions.
    #[test]
    fn a_real_installed_catalog_equals_pkg_list() {
        let out = run(&ARTIFACT, "var/pkg/state/installed/catalog.base.C", &fixture("ips-packages/catalog.base.C"), 0);
        insta::assert_snapshot!(out);
        let list = String::from_utf8(fixture("ips-packages/pkg-list.txt")).unwrap();
        let mut listed = 0;
        for line in list.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            // `name version IFO` or `name (publisher) version IFO`.
            let (name, version) = (words[0], if words[1].starts_with('(') { words[2] } else { words[1] });
            let component = version.split('-').next().unwrap();
            assert!(
                out.contains(&format!(r#""name":"{name}","version":"{component},"#))
                    || out.contains(&format!(r#""name":"{name}","version":"{version}"#)),
                "{line}\n{out}"
            );
            listed += 1;
        }
        assert_eq!(listed, out.lines().filter(|l| l.starts_with('{')).count());
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(timeline.contains("package_installed"), "{timeline}");
    }

    /// `_SIGNATURE` and `_FEATURE` are the catalog's own keys, not publishers.
    #[test]
    fn catalog_keys_that_start_with_an_underscore_are_not_publishers() {
        let catalog = br#"{"_FEATURE":["x"],"_SIGNATURE":{"sha-1":"00"},"p":{"a":[{"version":"1.0"}]}}"#;
        let out = run(&ARTIFACT, "var/pkg/state/installed/catalog.base.C", catalog, 0);
        assert!(!out.contains("--- warning") && out.contains(r#""version":"1.0""#), "{out}");
        assert!(!out.contains("_SIGNATURE") && !out.contains("sha-1"), "{out}");
    }

    #[test]
    fn odd_and_damaged_catalogs() {
        assert!(run(&ARTIFACT, "var/pkg/state/installed/catalog.base.C", b"", 0).contains("not a JSON catalog"));
        assert!(run(&ARTIFACT, "var/pkg/state/installed/catalog.base.C", b"[1]", 0).contains("not a JSON object"));
        let out = run(
            &ARTIFACT,
            "var/pkg/state/installed/catalog.base.C",
            br#"{"p":{"a":[{"nope":1},{"version":"1.0","metadata":{"last-install":"bad"}}]},"q":5}"#,
            0,
        );
        assert!(
            out.contains("an entry has no version")
                && out.contains("publisher q: not a list")
                && out.contains(r#""version":"1.0","last_install":null"#),
            "{out}"
        );
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(
            &ARTIFACT,
            "var/pkg/state/installed/catalog.base.C",
            &fixture("ips-packages/catalog.base.C"),
        );
    }

    /// r151060 keeps the installed set in an SQLite catalog that also lists packages offered but not installed.
    #[test]
    fn the_sqlite_catalog_of_a_newer_image_reads_the_installed_rows_only() {
        let out = run(&ARTIFACT, "var/pkg/state/catalog.db", &fixture("ips-packages/catalog.db"), 0);
        insta::assert_snapshot!("sqlite", out);
        let list = String::from_utf8(fixture("ips-packages/pkg-list-r151060.txt")).unwrap();
        let rows = out.lines().filter(|l| l.starts_with('{')).count();
        assert_eq!(rows, list.lines().count(), "{out}");
        for line in list.lines() {
            let name = line.split_whitespace().next().unwrap();
            assert!(out.contains(&format!(r#""name":"{name}""#)), "{line}\n{out}");
        }
        assert!(out.contains(r#""last_install":"2026-10-22T"#) && out.contains("package_installed"), "{out}");
        assert_eq!(
            out.matches("\"publisher\":\"extra.omnios\"").count(),
            list.lines().filter(|l| l.contains("(extra.omnios)")).count()
        );
    }

    #[test]
    fn a_database_without_the_table_is_skipped() {
        let other = crate::testing::fixture("smf-repository/repository.db");
        assert!(!run(&ARTIFACT, "var/pkg/state/catalog.db", &other, 0).contains("package_installed"));
        super::super::never_panics(&ARTIFACT, "var/pkg/state/catalog.db", &fixture("ips-packages/catalog.db"));
    }
}

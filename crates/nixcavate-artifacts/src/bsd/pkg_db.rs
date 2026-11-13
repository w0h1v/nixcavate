//! Installed-package databases of FreeBSD (pkg(8), `var/db/pkg/local.sqlite`) and OpenBSD
//! (`pkg_add(1)`, one directory per package under `var/db/pkg/`).
//!
//! FreeBSD: the SQLite `packages` table of pkgng; `time` is when the package was installed
//! (rewritten on upgrade) and the `repository` annotation says where it came from. OpenBSD:
//! `+CONTENTS` is the packing list (`@name`, `@comment pkgpath=...`, `@arch`, ...). It holds no
//! install time, so the time is the modification time of the file as collected; the record
//! says so in `time_source`. OpenBSD has no single file every database has, so one task is
//! anchored on the `quirks` package that `pkg_add` installs first (the same pattern as
//! `pacman-db`) and walks every `+CONTENTS` itself; a database without `quirks` is not found.

use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::text::lossy;
use crate::{Artifact, Category, Input, FREEBSD, OPENBSD};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Pattern;
use serde::Serialize;
use std::borrow::Cow;

pub const PKG_DB: Artifact = Artifact::new(
    "pkg-db",
    "FreeBSD installed packages (pkg local.sqlite)",
    Category::Software,
    FREEBSD,
    &["var/db/pkg/local.sqlite"],
    parse_pkg,
)
.companions(&["var/db/pkg/local.sqlite-wal"]);

pub const OPENBSD_PKG_DB: Artifact = Artifact::new(
    "pkg-add-db",
    "OpenBSD installed packages (pkg_add database)",
    Category::Software,
    OPENBSD,
    &["var/db/pkg/quirks-*/+CONTENTS"],
    parse_openbsd,
)
// The walk reads every package's list; a compressed archive keeps only files some pattern names.
.companions(&["var/db/pkg/*/+CONTENTS", "var/db/pkg/*/+COMMENT"]);

#[derive(Serialize, Default)]
pub(crate) struct Package<'a> {
    /// The install time: pkg's `time` column, or the file time for OpenBSD (see `time_source`).
    pub(crate) time: Option<Timestamp>,
    /// `recorded` (the database says so) or `file mtime`.
    pub(crate) time_source: &'static str,
    pub(crate) package: Cow<'a, str>,
    pub(crate) version: Cow<'a, str>,
    /// The ports origin or pkgpath (`sysutils/tree`).
    pub(crate) origin: Cow<'a, str>,
    pub(crate) architecture: Cow<'a, str>,
    /// `explicit` or `dependency` (`automatic`).
    pub(crate) install_reason: &'static str,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) maintainer: Cow<'a, str>,
    /// When the package was built (pkgsrc `BUILD_DATE`), which is not when it was installed.
    pub(crate) build_time: Option<Timestamp>,
    pub(crate) prefix: Cow<'a, str>,
    /// The repository the package was installed from (FreeBSD annotation).
    pub(crate) repository: Cow<'a, str>,
    pub(crate) comment: Cow<'a, str>,
    pub(crate) locked: Option<bool>,
    pub(crate) package_path: String,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("installed {} {}", self.package, self.version);
        self.time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

fn parse_pkg(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["packages"])?;
    // The `repository` annotation: tag and value are rows of `annotation`. The tables may be
    // missing in a very old database; the packages are still listed then.
    let annotated = db.has_table("pkg_annotation") && db.has_table("annotation");
    let sql = if annotated {
        "SELECT p.name, p.version, p.origin, p.arch, p.automatic, p.flatsize, p.maintainer, p.prefix, p.comment, p.locked, p.time, \
         (SELECT v.annotation FROM pkg_annotation a JOIN annotation t ON t.annotation_id = a.tag_id \
          JOIN annotation v ON v.annotation_id = a.value_id WHERE a.package_id = p.id AND t.annotation = 'repository' LIMIT 1) \
         FROM packages p ORDER BY p.time, p.id"
    } else {
        "SELECT p.name, p.version, p.origin, p.arch, p.automatic, p.flatsize, p.maintainer, p.prefix, p.comment, p.locked, p.time, NULL \
         FROM packages p ORDER BY p.time, p.id"
    };
    let mut stmt = db.conn.prepare(sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = int_at(row, 10)
            .filter(|&t| t > 0)
            .and_then(|t| Timestamp::checked(t, 0, Precision::Seconds, Basis::Recorded));
        sink.emit(
            Loc::None,
            &Package {
                time,
                time_source: "recorded",
                package: text_at(row, 0).unwrap_or_default().into(),
                version: text_at(row, 1).unwrap_or_default().into(),
                origin: text_at(row, 2).unwrap_or_default().into(),
                architecture: text_at(row, 3).unwrap_or_default().into(),
                install_reason: if int_at(row, 4) == Some(0) { "explicit" } else { "dependency" },
                size_bytes: int_at(row, 5).and_then(|n| u64::try_from(n).ok()),
                maintainer: text_at(row, 6).unwrap_or_default().into(),
                build_time: None,
                prefix: text_at(row, 7).unwrap_or_default().into(),
                comment: text_at(row, 8).unwrap_or_default().into(),
                locked: int_at(row, 9).map(|n| n != 0),
                repository: text_at(row, 11).unwrap_or_default().into(),
                package_path: input.path.to_string(),
            },
        )?;
    }
    Ok(())
}

/// A packing list larger than this is cut: the interesting lines are at the top.
const MAX_CONTENTS: usize = 1 << 20;
/// The most packages one database walk reads.
const MAX_PACKAGES: usize = 200_000;

/// Splits `name-version` at the last `-` that is followed by a digit: `gettext-0.22.5p0` and
/// `py3-pip-23.3.1` (OpenBSD and pkgsrc write the flavour after the version: `-no_x11`).
pub(crate) fn split_name_version(full: &str) -> (&str, &str) {
    let mut cut = None;
    for (i, _) in full.match_indices('-') {
        if full[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            cut = Some(i);
            break;
        }
    }
    match cut {
        Some(i) => (&full[..i], &full[i + 1..]),
        None => (full, ""),
    }
}

fn parse_openbsd(input: &Input, sink: &mut Sink) -> Result<()> {
    let lists = Pattern::new("var/db/pkg/*/+CONTENTS");
    for (count, entry) in input.host.find(&lists).filter(|e| e.link.is_none()).enumerate() {
        if count >= MAX_PACKAGES {
            sink.warn(format!("more than {MAX_PACKAGES} packages: the rest are not read"));
            break;
        }
        let path = input.host.rel(entry);
        let data = match input.host.open(entry) {
            Ok(data) => data,
            Err(e) => {
                sink.warn(format!("{path}: cannot read: {e}"));
                continue;
            }
        };
        let text = lossy(&data[..data.len().min(MAX_CONTENTS)]);
        let (mut name, mut pkgpath, mut arch) = ("", "", "");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("@name ") {
                name = rest.trim();
            } else if let Some(rest) = line.strip_prefix("@comment pkgpath=") {
                pkgpath = rest.split_whitespace().next().unwrap_or_default();
            } else if let Some(rest) = line.strip_prefix("@arch ") {
                arch = rest.trim();
            } else if line.starts_with("@sha")
                || line.starts_with("@size")
                || (!line.starts_with('@') && !line.is_empty())
            {
                // The header of a packing list ends where the file list starts.
                break;
            }
        }
        if name.is_empty() {
            sink.warn(format!("{path}: no @name line"));
            continue;
        }
        let (package, version) = split_name_version(name);
        let comment = input
            .host
            .read(&path.replace("+CONTENTS", "+COMMENT"))
            .map(|c| lossy(&c[..c.len().min(4096)]).trim().to_string())
            .unwrap_or_default();
        sink.emit(
            Loc::None,
            &Package {
                time: (entry.mtime > 0).then(|| Timestamp::from_secs(entry.mtime, Basis::Recorded)),
                time_source: "file mtime",
                package: package.into(),
                version: version.into(),
                origin: pkgpath.into(),
                architecture: arch.into(),
                comment: comment.into(),
                install_reason: "",
                package_path: path,
                ..Package::default()
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn reads_a_real_pkg_database() {
        let out = run(&PKG_DB, "var/db/pkg/local.sqlite", &fixture("pkg-db/local.sqlite"), 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"repository\":\"FreeBSD\""));
    }

    #[test]
    fn a_file_that_is_not_a_database_is_skipped_or_failed() {
        assert!(run(&PKG_DB, "var/db/pkg/local.sqlite", b"hello", 0).contains("skipped: not an SQLite database"));
    }

    /// Two real packages of an OpenBSD 7.8 guest: `quirks` (the anchor) and `tree` (asked for by name).
    #[test]
    fn a_real_openbsd_package_database() {
        let files: Vec<(String, Vec<u8>)> = ["quirks-7.147/+CONTENTS", "tree-0.62/+CONTENTS", "tree-0.62/+COMMENT"]
            .iter()
            .filter(|f| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../../test_files/pkg-add-db/var/db/pkg/{f}"))
                    .exists()
            })
            .map(|f| (format!("var/db/pkg/{f}"), fixture(&format!("pkg-add-db/var/db/pkg/{f}"))))
            .collect();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        let out = run_on_host(&OPENBSD_PKG_DB, &refs, "var/db/pkg/quirks-7.147/+CONTENTS", 0);
        insta::assert_snapshot!("openbsd_pkg", out);
        assert!(
            out.contains(
                "\"package\":\"tree\",\"version\":\"0.62\",\"origin\":\"sysutils/tree\",\"architecture\":\"amd64\""
            ),
            "{out}"
        );
        assert!(out.contains("\"package\":\"quirks\",\"version\":\"7.147\""));
    }

    #[test]
    fn openbsd_packing_lists() {
        let quirks = b"@name quirks-7.76\n@comment pkgpath=devel/quirks\n@arch amd64\n@sha aaa\n";
        let tree = b"@name tree-2.1.1\n@comment pkgpath=sysutils/tree\n@arch amd64\nbin/tree\n";
        let files: [(&str, &[u8]); 4] = [
            ("var/db/pkg/quirks-7.76/+CONTENTS", quirks),
            ("var/db/pkg/tree-2.1.1/+CONTENTS", tree),
            ("var/db/pkg/tree-2.1.1/+COMMENT", b"list contents of directories in a tree-like format\n"),
            ("var/db/pkg/broken-1.0/+CONTENTS", b"@comment nothing\n"),
        ];
        let out = run_on_host(&OPENBSD_PKG_DB, &files, "var/db/pkg/quirks-7.76/+CONTENTS", 0);
        assert!(out.contains("\"package\":\"tree\",\"version\":\"2.1.1\",\"origin\":\"sysutils/tree\""), "{out}");
        assert!(out.contains("\"time_source\":\"file mtime\""));
        assert!(out.contains("--- warning: var/db/pkg/broken-1.0/+CONTENTS: no @name line"), "{out}");
    }

    #[test]
    fn names_split_at_the_version() {
        assert_eq!(split_name_version("gettext-runtime-0.22.5p0"), ("gettext-runtime", "0.22.5p0"));
        assert_eq!(split_name_version("py3-pip-23.3.1v0"), ("py3-pip", "23.3.1v0"));
        assert_eq!(split_name_version("noversion"), ("noversion", ""));
    }
}

//! NetBSD pkgsrc: the installed-package database (`pkg_install`) and pkgin's SQLite database.
//!
//! pkg_install keeps one directory per package below `PKG_DBDIR` (`/usr/pkg/pkgdb`, or
//! `/var/db/pkg` on older systems): `+CONTENTS` is the packing list (`@name tree-1.8.0`,
//! `@cwd /usr/pkg`), `+BUILD_INFO` has `KEY=value` lines (`PKGPATH`, `BUILD_DATE`, `MACHINE_ARCH`,
//! `MAINTAINER`), `+COMMENT` the one-line description, `+SIZE_PKG` the installed size, and
//! `+INSTALLED_INFO` holds `automatic=yes` for a package pulled in as a dependency. Nothing
//! records the install time: it is the modification time of `+CONTENTS` as collected (the
//! record says so in `time_source`). One task is anchored on `pkgdb.byfile.db`, the file index
//! every database has (a Berkeley DB 1.85 hash file that is not read), and walks the
//! directories itself, as `pacman-db` does. Checked against `pkg_info` on NetBSD 10.1.
//!
//! pkgin's `pkgin.db` (`var/db/pkgin/`) lists the installed packages in `LOCAL_PKG` with their
//! build date, and no install time; `PKG_KEEP` marks the packages that were asked for by name.

use super::pkg_db::{split_name_version, Package};
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::text::lossy;
use crate::{Artifact, Category, Input, NETBSD};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Basis, Loc, Result, Sink, Timestamp};

pub const PKGSRC_DB: Artifact = Artifact::new(
    "pkgsrc-db",
    "NetBSD pkgsrc installed packages (pkg_install database)",
    Category::Software,
    NETBSD,
    &["usr/pkg/pkgdb/pkgdb.byfile.db", "var/db/pkg/pkgdb.byfile.db"],
    parse_pkgdb,
)
// The walk reads each package's files; a compressed archive keeps only files some pattern names.
.companions(&[
    "usr/pkg/pkgdb/*/+CONTENTS",
    "usr/pkg/pkgdb/*/+BUILD_INFO",
    "usr/pkg/pkgdb/*/+COMMENT",
    "usr/pkg/pkgdb/*/+SIZE_PKG",
    "usr/pkg/pkgdb/*/+INSTALLED_INFO",
    "var/db/pkg/*/+CONTENTS",
    "var/db/pkg/*/+BUILD_INFO",
    "var/db/pkg/*/+COMMENT",
    "var/db/pkg/*/+SIZE_PKG",
    "var/db/pkg/*/+INSTALLED_INFO",
]);

pub const PKGIN: Artifact = Artifact::new(
    "pkgin-db",
    "NetBSD pkgin installed packages (pkgin.db)",
    Category::Software,
    NETBSD,
    &["var/db/pkgin/pkgin.db", "usr/pkg/var/db/pkgin/pkgin.db"],
    parse_pkgin,
)
.companions(&["var/db/pkgin/pkgin.db-wal"]);

/// `2026-04-28 08:05:49 +0000`: pkgsrc writes the build time in UTC.
fn build_time(text: &str) -> Option<Timestamp> {
    let (parsed, used) = parse_iso8601(text.get(..19)?.as_bytes())?;
    (used == 19 && text.get(19..)?.trim() == "+0000").then(|| Timestamp::from_secs(parsed.secs, Basis::Recorded))
}

const MAX_FILE: usize = 1 << 20;
const MAX_PACKAGES: usize = 200_000;

/// The value of `KEY=` in a `+BUILD_INFO`-style file.
fn key<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix('=')).unwrap_or_default().trim()
}

fn parse_pkgdb(input: &Input, sink: &mut Sink) -> Result<()> {
    let Some(dir) = input.path.strip_suffix("pkgdb.byfile.db") else { return Ok(()) };
    let own = |rel: &str| {
        rel.strip_prefix(dir).is_some_and(|rest| rest.strip_suffix("/+CONTENTS").is_some_and(|n| !n.contains('/')))
    };
    let lists = input.host.entries().iter().filter(|e| e.link.is_none() && own(&input.host.rel(e)));
    for (count, entry) in lists.enumerate() {
        if count >= MAX_PACKAGES {
            sink.warn(format!("more than {MAX_PACKAGES} packages: the rest are not read"));
            break;
        }
        let path = input.host.rel(entry);
        let Ok(data) = input.host.open(entry) else {
            sink.warn(format!("{path}: cannot read"));
            continue;
        };
        let text = lossy(&data[..data.len().min(MAX_FILE)]);
        let name = text.lines().find_map(|l| l.strip_prefix("@name ")).map(str::trim).unwrap_or_default();
        if name.is_empty() {
            sink.warn(format!("{path}: no @name line"));
            continue;
        }
        let cwd = text.lines().find_map(|l| l.strip_prefix("@cwd ")).map(str::trim).unwrap_or_default().to_string();
        let sibling = |file: &str| input.host.read_text(&path.replace("+CONTENTS", file)).unwrap_or_default();
        let build = sibling("+BUILD_INFO");
        let comment = sibling("+COMMENT");
        let (package, version) = split_name_version(name);
        sink.emit(
            Loc::None,
            &Package {
                time: (entry.mtime > 0).then(|| Timestamp::from_secs(entry.mtime, Basis::Recorded)),
                time_source: "file mtime",
                package: package.to_string().into(),
                version: version.to_string().into(),
                origin: key(&build, "PKGPATH").to_string().into(),
                architecture: key(&build, "MACHINE_ARCH").to_string().into(),
                install_reason: if key(&sibling("+INSTALLED_INFO"), "automatic") == "yes" {
                    "dependency"
                } else {
                    "explicit"
                },
                size_bytes: sibling("+SIZE_PKG").trim().parse().ok(),
                maintainer: key(&build, "MAINTAINER").to_string().into(),
                build_time: build_time(key(&build, "BUILD_DATE")),
                prefix: cwd.into(),
                comment: comment.lines().next().unwrap_or_default().to_string().into(),
                package_path: path,
                ..Package::default()
            },
        )?;
    }
    Ok(())
}

fn parse_pkgin(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["LOCAL_PKG"])?;
    let mut stmt = db
        .conn
        .prepare(
            "SELECT PKGNAME, PKGVERS, PKGPATH, COMMENT, SIZE_PKG, PKG_KEEP, BUILD_DATE FROM LOCAL_PKG ORDER BY PKG_ID",
        )
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        sink.emit(
            Loc::None,
            &Package {
                time_source: "none",
                package: text_at(row, 0).unwrap_or_default().into(),
                version: text_at(row, 1).unwrap_or_default().into(),
                origin: text_at(row, 2).unwrap_or_default().into(),
                comment: text_at(row, 3).unwrap_or_default().into(),
                size_bytes: int_at(row, 4).and_then(|n| u64::try_from(n).ok()),
                install_reason: if int_at(row, 5) == Some(1) { "explicit" } else { "dependency" },
                build_time: text_at(row, 6).as_deref().and_then(build_time),
                package_path: input.path.to_string(),
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

    fn db_files() -> Vec<(String, Vec<u8>)> {
        let mut files =
            vec![("usr/pkg/pkgdb/pkgdb.byfile.db".to_string(), fixture("pkgsrc-db/usr/pkg/pkgdb/pkgdb.byfile.db"))];
        for pkg in ["tree-1.8.0", "oniguruma-6.9.10"] {
            for f in ["+CONTENTS", "+BUILD_INFO", "+COMMENT", "+SIZE_PKG", "+INSTALLED_INFO"] {
                let path = format!("pkgsrc-db/usr/pkg/pkgdb/{pkg}/{f}");
                if std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files").join(&path).exists() {
                    files.push((format!("usr/pkg/pkgdb/{pkg}/{f}"), fixture(&path)));
                }
            }
        }
        files
    }

    /// Two real packages of a NetBSD 10.1 guest; `pkg_info` listed `tree-1.8.0` and `oniguruma-6.9.10`
    /// (the second pulled in by `jq`, so `+INSTALLED_INFO` says `automatic=yes`).
    #[test]
    fn reads_the_installed_packages() {
        let files = db_files();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        let out = run_on_host(&PKGSRC_DB, &refs, "usr/pkg/pkgdb/pkgdb.byfile.db", 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"package\":\"tree\",\"version\":\"1.8.0\",\"origin\":\"sysutils/tree\""));
        assert!(out.contains("\"package\":\"oniguruma\"") && out.contains("\"install_reason\":\"dependency\""));
        assert!(out.contains("\"architecture\":\"x86_64\"") && out.contains("\"prefix\":\"/usr/pkg\""));
    }

    #[test]
    fn a_package_without_a_name_is_a_warning() {
        let mut files = db_files();
        files.push(("usr/pkg/pkgdb/broken-1.0/+CONTENTS".to_string(), b"@comment nothing\n".to_vec()));
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        let out = run_on_host(&PKGSRC_DB, &refs, "usr/pkg/pkgdb/pkgdb.byfile.db", 0);
        assert!(out.contains("--- warning: usr/pkg/pkgdb/broken-1.0/+CONTENTS: no @name line"), "{out}");
    }

    #[test]
    fn pkgin_lists_the_installed_packages_with_their_build_date() {
        let out = run(&PKGIN, "var/db/pkgin/pkgin.db", &fixture("pkgin-db/pkgin.db"), 0);
        insta::assert_snapshot!("pkgin", out);
        assert!(out.contains("\"package\":\"tree\"") && out.contains("\"build_time\":\"2026-04-28T08:05:49Z\""));
        assert!(run(&PKGIN, "var/db/pkgin/pkgin.db", b"hello", 0).contains("skipped: not an SQLite database"));
    }
}

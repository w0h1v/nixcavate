//! The installed-package database of RPM-based systems: `rpmdb.sqlite` (RPM 4.16 and later)
//! and the older Berkeley DB hash file `var/lib/rpm/Packages` (RHEL 8 and earlier, Amazon
//! Linux 2, older SUSE; read by [`super::bdb_hash`]). Format: the RPM reference manual,
//! "header format" and "RPM tags". The file's content, not its name, picks the reader.
//!
//! Both hold one header blob per package, in on-disk form: big-endian `index_count` and
//! `data_size`, `index_count` 16-byte entries `{tag, type, offset, count}`, then the data
//! store. Every number comes from the evidence, so each access is bounds-checked. In the
//! Berkeley DB file the key is the package instance number; instance 0 is RPM's own
//! bookkeeping record, not a header, and is skipped.

use super::bdb_hash::{self, HashDb};
use crate::sqlite::{open, sql_error};
use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "rpm-db",
    "Installed RPM packages",
    Category::Software,
    LINUX,
    &["var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"],
    parse,
)
.companions(&["var/lib/rpm/rpmdb.sqlite-wal", "usr/lib/sysimage/rpm/rpmdb.sqlite-wal"]);

const NAME: u32 = 1000;
const VERSION: u32 = 1001;
const RELEASE: u32 = 1002;
const EPOCH: u32 = 1003;
const SUMMARY: u32 = 1004;
const BUILDTIME: u32 = 1006;
const INSTALLTIME: u32 = 1008;
const SIZE: u32 = 1009;
const VENDOR: u32 = 1011;
const LICENSE: u32 = 1014;
const PACKAGER: u32 = 1015;
const ARCH: u32 = 1022;
const SOURCERPM: u32 = 1044;
/// Packages larger than 4 GiB carry their size here instead of in `SIZE`.
const LONGSIZE: u32 = 5009;

const TYPE_INT32: u32 = 4;
const TYPE_INT64: u32 = 5;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

/// A parsed header: the index and the data store, both borrowed from the blob.
struct Header<'a> {
    index: &'a [u8],
    data: &'a [u8],
}

impl<'a> Header<'a> {
    fn new(blob: &'a [u8]) -> Option<Self> {
        let count = u32::from_be_bytes(blob.get(0..4)?.try_into().ok()?) as usize;
        let rest = blob.get(8..)?;
        // A count larger than the bytes present is corrupt; never allocate or loop by it.
        let index_len = count.checked_mul(16)?;
        Some(Header { index: rest.get(..index_len)?, data: &rest[index_len..] })
    }

    /// `(type, offset, count)` of the first entry with this tag.
    fn find(&self, tag: u32) -> Option<(u32, usize, u32)> {
        self.index.chunks_exact(16).find_map(|entry| {
            let word = |at: usize| u32::from_be_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]]);
            (word(0) == tag).then(|| (word(4), word(8) as usize, word(12)))
        })
    }

    /// The tag's string, or the first one of an internationalised string.
    fn string(&self, tag: u32) -> Cow<'a, str> {
        let Some((kind, offset, _)) = self.find(tag) else { return Cow::Borrowed("") };
        if kind != TYPE_STRING && kind != TYPE_I18NSTRING {
            return Cow::Borrowed("");
        }
        let Some(tail) = self.data.get(offset..) else { return Cow::Borrowed("") };
        lossy(&tail[..memchr::memchr(0, tail).unwrap_or(tail.len())])
    }

    fn int32(&self, tag: u32) -> Option<u32> {
        let (kind, offset, count) = self.find(tag)?;
        if kind != TYPE_INT32 || count == 0 {
            return None;
        }
        let bytes = self.data.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    fn int64(&self, tag: u32) -> Option<u64> {
        let (kind, offset, count) = self.find(tag)?;
        if kind != TYPE_INT64 || count == 0 {
            return None;
        }
        let bytes = self.data.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }
}

#[derive(Serialize)]
struct Package<'a> {
    #[serde(rename = "time")]
    install_time: Option<Timestamp>,
    package: Cow<'a, str>,
    epoch: Option<u32>,
    version: Cow<'a, str>,
    release: Cow<'a, str>,
    architecture: Cow<'a, str>,
    build_time: Option<Timestamp>,
    size_bytes: Option<u64>,
    vendor: Cow<'a, str>,
    packager: Cow<'a, str>,
    license: Cow<'a, str>,
    summary: Cow<'a, str>,
    source_rpm: Cow<'a, str>,
}

impl Record for Package<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let arch = if self.architecture.is_empty() { String::new() } else { format!(".{}", self.architecture) };
        let message = format!("installed {}-{}-{}{arch}", self.package, self.version, self.release);
        self.install_time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

fn package(blob: &[u8]) -> Option<Package<'_>> {
    let header = Header::new(blob)?;
    let package = header.string(NAME);
    if package.is_empty() {
        return None;
    }
    let time = |tag| header.int32(tag).map(|secs| Timestamp::from_secs(secs as i64, Basis::Recorded));
    Some(Package {
        install_time: time(INSTALLTIME),
        package,
        epoch: header.int32(EPOCH),
        version: header.string(VERSION),
        release: header.string(RELEASE),
        architecture: header.string(ARCH),
        build_time: time(BUILDTIME),
        size_bytes: header.int64(LONGSIZE).or_else(|| header.int32(SIZE).map(u64::from)),
        vendor: header.string(VENDOR),
        packager: header.string(PACKAGER),
        license: header.string(LICENSE),
        summary: header.string(SUMMARY),
        source_rpm: header.string(SOURCERPM),
    })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if bdb_hash::is_bdb(input.data) {
        return parse_bdb(input.data, sink);
    }
    if input.path.ends_with("/Packages") && !input.data.starts_with(b"SQLite format 3\0") {
        return Err(Error::skipped("not a Berkeley DB or SQLite database"));
    }
    parse_sqlite(input, sink)
}

fn parse_bdb(data: &[u8], sink: &mut Sink) -> Result<()> {
    let db = HashDb::open(data)?;
    db.for_each(|entry| {
        let instance = <[u8; 4]>::try_from(entry.key)
            .map(|k| if db.big_endian { u32::from_be_bytes(k) } else { u32::from_le_bytes(k) })
            .ok();
        if instance == Some(0) {
            return Ok(());
        }
        let name = instance.map_or_else(|| "with an unreadable key".to_string(), |n| n.to_string());
        match entry.value {
            Ok(blob) => match package(blob) {
                Some(record) => sink.emit(Loc::Offset(entry.page_offset), &record),
                None => {
                    sink.warn(format!("package {name}: unreadable header"));
                    Ok(())
                }
            },
            Err(why) => {
                sink.warn(format!("package {name} (page at offset {}): {why}", entry.page_offset));
                Ok(())
            }
        }
    })
}

fn parse_sqlite(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open(input)?;
    if !db.has_table("Packages") {
        return Err(Error::skipped("no Packages table"));
    }
    let mut statement = db.conn.prepare("SELECT hnum, blob FROM Packages ORDER BY hnum").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let hnum: i64 = row.get(0).unwrap_or(-1);
        match row.get_ref(1).map_err(sql_error)?.as_blob() {
            Ok(blob) => match package(blob) {
                Some(record) => sink.emit(Loc::None, &record)?,
                None => sink.warn(format!("package {hnum}: unreadable header")),
            },
            Err(_) => sink.warn(format!("package {hnum}: not a blob")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    fn blobs() -> Vec<Vec<u8>> {
        let path = std::env::temp_dir().join(format!("nixcavate-rpmdb-{}.sqlite", std::process::id()));
        std::fs::write(&path, fixture("rpm-db/rpmdb.sqlite")).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let out = conn
            .prepare("SELECT blob FROM Packages ORDER BY hnum")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let _ = std::fs::remove_file(path);
        out
    }

    #[test]
    fn parses_installed_packages() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/lib/rpm/rpmdb.sqlite", &fixture("rpm-db/rpmdb.sqlite"), 0));
    }

    #[test]
    fn rejects_other_files() {
        assert!(run(&ARTIFACT, "var/lib/rpm/rpmdb.sqlite", b"", 0).contains("skipped: not an SQLite database"));
        let text = run(&ARTIFACT, "var/lib/rpm/rpmdb.sqlite", b"just text, not a database", 0);
        assert!(text.contains("skipped: not an SQLite database"), "{text}");
        let other = fixture("dnf-history/history.sqlite");
        let text = run_on_host(
            &ARTIFACT,
            &[("usr/lib/sysimage/rpm/rpmdb.sqlite", &other)],
            "usr/lib/sysimage/rpm/rpmdb.sqlite",
            0,
        );
        assert!(text.contains("skipped: no Packages table"), "{text}");
    }

    #[test]
    fn corrupt_headers_never_panic() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for blob in blobs() {
            assert!(package(&blob).is_some());
            for len in (0..blob.len()).step_by(7) {
                let _ = package(&blob[..len]);
            }
            for _ in 0..2000 {
                let mut copy = blob.clone();
                for _ in 0..1 + next() % 4 {
                    let at = (next() as usize) % copy.len();
                    copy[at] ^= 1 << (next() % 8);
                }
                // Hit the index and the counts most often: that is where sizes live.
                let at = (next() as usize) % copy.len().min(300);
                copy[at] = next() as u8;
                let _ = package(&copy);
            }
        }
    }

    #[test]
    fn parses_berkeley_db_packages() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/lib/rpm/Packages", &fixture("rpm-db/Packages"), 0));
    }

    #[test]
    fn parses_big_endian_berkeley_db_packages() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/lib/rpm/Packages", &fixture("rpm-db/Packages-s390x"), 0));
    }

    #[test]
    fn skips_other_packages_files() {
        let text = run(&ARTIFACT, "var/lib/rpm/Packages", b"", 0);
        assert!(text.contains("skipped: not a Berkeley DB or SQLite database"), "{text}");
        let mut btree = fixture("rpm-db/Packages");
        btree[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        let text = run(&ARTIFACT, "var/lib/rpm/Packages", &btree, 0);
        assert!(text.contains("skipped: Berkeley DB btree file, not a hash"), "{text}");
        // An SQLite database under the old name is still read.
        let text = run(&ARTIFACT, "var/lib/rpm/Packages", &fixture("rpm-db/rpmdb.sqlite"), 0);
        assert_eq!(text.matches("\"package\":").count(), 5, "{text}");
    }

    #[test]
    fn bad_berkeley_db_values_are_warnings() {
        // Break the start of every overflow page: each header now declares 2^32 - 1 entries.
        let mut file = fixture("rpm-db/Packages");
        for page in file.chunks_exact_mut(4096).filter(|page| page[25] == 7) {
            page[26..30].fill(0xff);
        }
        let text = run(&ARTIFACT, "var/lib/rpm/Packages", &file, 0);
        assert_eq!(text.matches("unreadable header").count(), 5, "{text}");
        assert!(!text.contains("\"package\":"), "{text}");
    }

    /// Reads a Berkeley DB file the way `parse_bdb` does and returns the records found.
    fn bdb_packages(data: &[u8]) -> usize {
        let mut found = 0;
        if let Ok(db) = HashDb::open(data) {
            db.for_each(|entry| {
                found += entry.value.ok().and_then(package).is_some() as usize;
                Ok(())
            })
            .unwrap();
        }
        found
    }

    #[test]
    fn corrupt_berkeley_db_files_never_panic() {
        let started = std::time::Instant::now();
        for name in ["rpm-db/Packages", "rpm-db/Packages-s390x"] {
            let file = fixture(name);
            assert_eq!(bdb_packages(&file), 5);
            // Every page boundary (dangling overflow references), and odd lengths.
            for len in (0..file.len()).step_by(512).chain((0..file.len()).step_by(997)) {
                assert!(bdb_packages(&file[..len]) <= 5);
            }
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = move || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            for _ in 0..1000 {
                let mut copy = file.clone();
                for _ in 0..1 + next() % 8 {
                    let at = (next() as usize) % copy.len();
                    copy[at] ^= 1 << (next() % 8);
                }
                // Hit page headers and hash pages most often: that is where the numbers live.
                let page = 4096 * ((next() as usize) % (copy.len() / 4096));
                let at = page + (next() as usize) % 64;
                copy[at] = next() as u8;
                assert!(bdb_packages(&copy) <= 5 + 4096 / 4);
            }
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(60), "{:?}", started.elapsed());
    }

    #[test]
    fn a_bad_blob_is_a_warning_not_a_failure() {
        let path = std::env::temp_dir().join(format!("nixcavate-rpmdb-bad-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)", []).unwrap();
        conn.execute("INSERT INTO Packages VALUES (1, x'0000ffff00000000')", []).unwrap();
        conn.execute("INSERT INTO Packages VALUES (2, 'text')", []).unwrap();
        drop(conn);
        let data = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let text = run(&ARTIFACT, "var/lib/rpm/rpmdb.sqlite", &data, 0);
        assert!(text.contains("package 1: unreadable header") && text.contains("package 2: not a blob"), "{text}");
    }
}

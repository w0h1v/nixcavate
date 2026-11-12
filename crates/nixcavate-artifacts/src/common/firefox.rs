//! Firefox browsing history and downloads: `places.sqlite`. Format reference: Mozilla's Places
//! database documentation (`toolkit/components/places`: `moz_places`, `moz_historyvisits`,
//! `moz_annos`) and `nsINavHistoryService` for the visit types. Modern Firefox keeps downloads
//! as annotations on the downloaded URL's place: the destination file and a JSON `metaData`.

use super::chromium::{download_message, profile_of, visit_message};
use crate::common::home::user_from_path;
use crate::macos::plist_util::or_warn;
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;

pub const HISTORY: Artifact = Artifact::new(
    "firefox-history",
    "Firefox browsing history",
    Category::Activity,
    ANY_OS,
    &[
        "home/*/.mozilla/firefox/*/places.sqlite",
        "home/*/snap/firefox/common/.mozilla/firefox/*/places.sqlite",
        "root/.mozilla/firefox/*/places.sqlite",
        "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite",
    ],
    parse_history,
)
.companions(WAL);

pub const DOWNLOADS: Artifact =
    Artifact::new("firefox-downloads", "Firefox downloads", Category::Activity, ANY_OS, HISTORY.paths, parse_downloads)
        .companions(WAL);

const WAL: &[&str] = &[
    "home/*/.mozilla/firefox/*/places.sqlite-wal",
    "home/*/snap/firefox/common/.mozilla/firefox/*/places.sqlite-wal",
    "root/.mozilla/firefox/*/places.sqlite-wal",
    "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite-wal",
];

/// PRTime: microseconds since the Unix epoch; `None` when it does not fit 1677-2262.
fn prtime(micros: i64) -> Option<Timestamp> {
    Timestamp::checked(
        micros.div_euclid(1_000_000),
        micros.rem_euclid(1_000_000) as u32 * 1000,
        Precision::Micros,
        Basis::Recorded,
    )
}

/// A PRTime read from a row or JSON value; 0 and NULL mean unset.
fn prtime_of(sink: &mut Sink, what: &str, micros: Option<i64>) -> Option<Timestamp> {
    or_warn(sink, what, micros.filter(|&m| m > 0), prtime)
}

fn visit_type(value: Option<i64>) -> Option<Cow<'static, str>> {
    Some(Cow::Borrowed(match value? {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

#[derive(Serialize)]
struct Visit<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    profile: &'a str,
    url: Option<String>,
    title: Option<String>,
    visit_count: Option<i64>,
    visit_type: Option<Cow<'static, str>>,
    from_visit: Option<i64>,
    typed: Option<bool>,
    frecency: Option<i64>,
}

impl Record for Visit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "url_visited", visit_message(self.user, self.url.as_deref(), self.title.as_deref())))
            .into_iter()
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["moz_places", "moz_historyvisits"])?;
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT v.visit_date, p.url, p.title, p.visit_count, v.visit_type, v.from_visit, p.typed, p.frecency \
                 FROM moz_historyvisits v LEFT JOIN {} p ON p.id = v.place_id ORDER BY v.visit_date, v.id",
            unique_rows("moz_places", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = prtime_of(sink, "visit_date", int_at(row, 0));
        sink.emit(
            Loc::None,
            &Visit {
                time,
                user,
                profile,
                url: text_at(row, 1),
                title: text_at(row, 2),
                visit_count: int_at(row, 3),
                visit_type: visit_type(int_at(row, 4)),
                from_visit: int_at(row, 5),
                typed: int_at(row, 6).map(|n| n != 0),
                frecency: int_at(row, 7),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Download<'a> {
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    user: &'a str,
    profile: &'a str,
    url: Option<String>,
    target_path: Option<String>,
    state: Option<Cow<'static, str>>,
    size_bytes: Option<i64>,
}

impl Record for Download<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| {
                Event::new(
                    t,
                    "file_downloaded",
                    download_message(self.user, self.url.as_deref(), self.target_path.as_deref()),
                )
            })
            .into_iter()
    }
}

/// `file:///home/alice/a%20b` to `/home/alice/a b`.
fn path_of_file_uri(uri: &str) -> String {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = |d: Option<&u8>| d.and_then(|&d| (d as char).to_digit(16));
        match (b, hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `nsIDownloadManager` / `DownloadsCommon` state numbers.
fn download_state(value: i64) -> Cow<'static, str> {
    Cow::Borrowed(match value {
        -1 => "not_started",
        0 => "downloading",
        1 => "finished",
        2 => "failed",
        3 => "canceled",
        4 => "paused",
        5 => "queued",
        6 => "blocked_parental",
        7 => "scanning",
        8 => "dirty",
        9 => "blocked_policy",
        n => return Cow::Owned(format!("unknown({n})")),
    })
}

fn parse_downloads(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["moz_places", "moz_annos", "moz_anno_attributes"])?;
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT p.url, a.dateAdded, a.content, \
                 (SELECT m.content FROM moz_annos m JOIN moz_anno_attributes t ON t.id = m.anno_attribute_id \
                  WHERE m.place_id = a.place_id AND t.name = 'downloads/metaData' LIMIT 1) \
                 FROM moz_annos a JOIN {} n ON n.id = a.anno_attribute_id \
                 AND n.name = 'downloads/destinationFileURI' LEFT JOIN {} p ON p.id = a.place_id \
                 ORDER BY a.dateAdded, a.id",
            unique_rows("moz_anno_attributes", "id"),
            unique_rows("moz_places", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let meta: Option<Value> = text_at(row, 3).and_then(|t| serde_json::from_str(&t).ok());
        let meta_int = |key: &str| meta.as_ref().and_then(|m| m.get(key)).and_then(Value::as_i64);
        let time = prtime_of(sink, "dateAdded", int_at(row, 1));
        let end = meta_int("endTime").map(|ms| ms.saturating_mul(1000));
        let end_time = prtime_of(sink, "endTime", end);
        sink.emit(
            Loc::None,
            &Download {
                time,
                end_time,
                user,
                profile,
                url: text_at(row, 0),
                target_path: text_at(row, 2).map(|u| path_of_file_uri(&u)),
                state: meta_int("state").map(download_state),
                size_bytes: meta_int("fileSize"),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "home/alice/.mozilla/firefox/abcd1234.default-release/places.sqlite";

    #[test]
    fn parses_history() {
        insta::assert_snapshot!(run(&HISTORY, PATH, &fixture("firefox-history/places.sqlite"), 0));
    }

    #[test]
    fn parses_downloads() {
        insta::assert_snapshot!(run(&DOWNLOADS, PATH, &fixture("firefox-history/places.sqlite"), 0));
    }

    #[test]
    fn duplicate_place_ids_do_not_multiply_rows() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE moz_places(id INTEGER, url TEXT, title TEXT, visit_count, typed, frecency);
             CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type, from_visit);
             CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content, dateAdded);
             CREATE TABLE moz_anno_attributes(id INTEGER, name TEXT);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_places SELECT 1, 'http://x/', 't', 1, 0, 0 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_anno_attributes SELECT 1, 'downloads/destinationFileURI' FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_historyvisits(place_id, visit_date, visit_type) SELECT 1, 1700000000000000, 1 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_annos(place_id, anno_attribute_id, content, dateAdded) SELECT 1, 1, 'file:///a', 1700000000000000 FROM c;",
        );
        assert_eq!(run(&HISTORY, PATH, &db, 0).matches("\"visit_type\":").count(), 200);
        assert_eq!(run(&DOWNLOADS, PATH, &db, 0).matches("\"target_path\":").count(), 200);
    }

    #[test]
    fn out_of_range_prtime_is_dropped() {
        assert!(prtime(1_700_000_000_000_000).is_some());
        assert!(prtime(i64::MAX).is_none());
        assert_eq!(download_state(5), "queued");
        assert_eq!(download_state(7), "scanning");
    }

    #[test]
    fn decodes_file_uris() {
        assert_eq!(path_of_file_uri("file:///home/a%20b/%e2%82%ac%zz%4"), "/home/a b/\u{20ac}%zz%4");
    }

    #[test]
    fn skips_non_databases_and_other_databases() {
        for artifact in [&HISTORY, &DOWNLOADS] {
            assert!(run(artifact, PATH, b"just some text\n", 0).contains("--- skipped"));
            assert!(run(artifact, PATH, b"", 0).contains("--- skipped"));
            let chromium = fixture("chromium-history/History");
            assert!(run(artifact, PATH, &chromium, 0).contains("--- skipped: no "));
        }
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("firefox-history/places.sqlite");
        for artifact in [&HISTORY, &DOWNLOADS] {
            for len in (0..data.len()).step_by(8192) {
                run(artifact, PATH, &data[..len], 0);
            }
            let mut seed = 99u32;
            for _ in 0..8 {
                let mut copy = data.clone();
                for _ in 0..16 {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    let at = (seed as usize >> 4) % copy.len().min(32768);
                    copy[at] ^= 0xff;
                }
                run(artifact, PATH, &copy, 0);
            }
        }
    }
}

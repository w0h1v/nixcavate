//! Safari history and downloads. `History.db` is SQLite (`history_items`, `history_visits`);
//! `Downloads.plist` is a property list with a `DownloadHistory` array. Neither format is
//! formally published; the layouts follow Safari's own files. Times are Mac absolute time
//! (seconds since 2001-01-01 UTC).

use super::plist_util::{date, mac_time, or_warn, parse};
use crate::common::chromium::{download_message, visit_message};
use crate::common::home::user_from_path;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const HISTORY: Artifact = Artifact::new(
    "safari-history",
    "Safari browsing history",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Safari/History.db"],
    parse_history,
)
.companions(&["Users/*/Library/Safari/History.db-wal"]);

pub const DOWNLOADS: Artifact = Artifact::new(
    "safari-downloads",
    "Safari downloads",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Safari/Downloads.plist"],
    parse_downloads,
);

#[derive(Serialize)]
struct Visit<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    url: Option<String>,
    title: Option<String>,
    visit_count: Option<i64>,
    load_successful: Option<bool>,
    redirect_source: Option<i64>,
    redirect_destination: Option<i64>,
    origin: Option<i64>,
}

impl Record for Visit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "url_visited", visit_message(self.user, self.url.as_deref(), self.title.as_deref())))
            .into_iter()
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["history_items", "history_visits"])?;
    let user = user_from_path(input.path);
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT v.visit_time, i.url, v.title, i.visit_count, v.load_successful, v.redirect_source, \
                 v.redirect_destination, v.origin FROM history_visits v \
                 LEFT JOIN {} i ON i.id = v.history_item ORDER BY v.visit_time, v.id",
            unique_rows("history_items", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        // Zero is Safari's "unset".
        let time = or_warn(sink, "visit_time", real_at(row, 0).filter(|&t| t != 0.0), mac_time);
        sink.emit(
            Loc::None,
            &Visit {
                time,
                user,
                url: text_at(row, 1),
                title: text_at(row, 2),
                visit_count: int_at(row, 3),
                load_successful: int_at(row, 4).map(|n| n != 0),
                redirect_source: int_at(row, 5),
                redirect_destination: int_at(row, 6),
                origin: int_at(row, 7),
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
    url: Option<String>,
    target_path: Option<String>,
    total_bytes: Option<i64>,
    received_bytes: Option<i64>,
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

/// A plist date; a date outside 1677-2262 is dropped with a warning.
fn date_time(sink: &mut Sink, entry: &plist::Dictionary, key: &str) -> Option<Timestamp> {
    let value = entry.get(key)?;
    let time = date(value);
    if time.is_none() {
        sink.warn(format!("{key} is not a valid time; left empty"));
    }
    time
}

fn parse_downloads(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = parse(input.data)?;
    let entries = root
        .as_dictionary()
        .and_then(|d| d.get("DownloadHistory"))
        .and_then(Value::as_array)
        .ok_or_else(|| Error::skipped("no DownloadHistory array"))?;
    let user = user_from_path(input.path);
    let mut records = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_dictionary() else {
            sink.warn("DownloadHistory entry is not a dictionary");
            continue;
        };
        let text = |key: &str| entry.get(key).and_then(Value::as_string).map(str::to_owned);
        let int = |key: &str| {
            let value = entry.get(key)?;
            value.as_signed_integer().or_else(|| value.as_real().map(|f| f as i64))
        };
        records.push(Download {
            time: date_time(sink, entry, "DownloadEntryDateAddedKey"),
            end_time: date_time(sink, entry, "DownloadEntryDateFinishedKey"),
            user,
            url: text("DownloadEntryURL"),
            target_path: text("DownloadEntryPath"),
            total_bytes: int("DownloadEntryProgressTotalToLoad"),
            received_bytes: int("DownloadEntryProgressBytesSoFar"),
        });
    }
    // The plist is in insertion order; the output is by time.
    records.sort_by_key(|r| r.time.map(|t| t.utc));
    for record in &records {
        sink.emit(Loc::None, record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const DB: &str = "Users/alice/Library/Safari/History.db";
    const PLIST: &str = "Users/alice/Library/Safari/Downloads.plist";

    #[test]
    fn parses_history() {
        insta::assert_snapshot!(run(&HISTORY, DB, &fixture("safari-history/History.db"), 0));
    }

    #[test]
    fn parses_downloads() {
        insta::assert_snapshot!(run(&DOWNLOADS, PLIST, &fixture("safari-downloads/Downloads.plist"), 0));
    }

    #[test]
    fn duplicate_item_ids_do_not_multiply_rows() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE history_items(id INTEGER, url TEXT, visit_count);
             CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title, load_successful, redirect_source, redirect_destination, origin);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO history_items SELECT 1, 'http://x/', 1 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO history_visits(history_item, visit_time) SELECT 1, 7.0e8 FROM c;",
        );
        assert_eq!(run(&HISTORY, DB, &db, 0).matches("\"origin\":").count(), 200);
    }

    #[test]
    fn dates_outside_the_range_are_dropped() {
        let xml = "<plist version=\"1.0\"><dict><key>DownloadHistory</key><array><dict>\
            <key>DownloadEntryURL</key><string>http://x/</string>\
            <key>DownloadEntryDateAddedKey</key><date>9999-01-01T00:00:00Z</date></dict></array></dict></plist>";
        let out = run(&DOWNLOADS, PLIST, xml.as_bytes(), 0);
        assert!(out.contains("\"time\":null") && out.contains("not a valid time"), "{out}");
    }

    #[test]
    fn skips_foreign_files() {
        assert!(run(&HISTORY, DB, b"text\n", 0).contains("--- skipped"));
        assert!(run(&HISTORY, DB, &fixture("firefox-history/places.sqlite"), 0).contains("--- skipped: no "));
        assert!(run(&DOWNLOADS, PLIST, b"", 0).contains("--- skipped: empty"));
        let other = plist::Value::Dictionary(plist::Dictionary::new());
        let mut data = Vec::new();
        other.to_writer_xml(&mut data).unwrap();
        assert!(run(&DOWNLOADS, PLIST, &data, 0).contains("--- skipped: no DownloadHistory"));
    }

    #[test]
    fn damaged_files_do_not_panic() {
        let db = fixture("safari-history/History.db");
        for len in (0..db.len()).step_by(1024) {
            run(&HISTORY, DB, &db[..len], 0);
        }
        let plist = fixture("safari-downloads/Downloads.plist");
        for len in 0..plist.len() {
            run(&DOWNLOADS, PLIST, &plist[..len], 0);
        }
        let mut seed = 7u32;
        for _ in 0..200 {
            let mut copy = plist.clone();
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let at = (seed as usize >> 4) % copy.len();
            copy[at] ^= 0xff;
            run(&DOWNLOADS, PLIST, &copy, 0);
        }
        for i in 0..db.len().min(8192) {
            if i % 97 == 0 {
                let mut copy = db.clone();
                copy[i] ^= 0xff;
                run(&HISTORY, DB, &copy, 0);
            }
        }
    }
}

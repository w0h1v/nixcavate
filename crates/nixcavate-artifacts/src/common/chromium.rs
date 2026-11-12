//! Chromium-family browser history and downloads (Chrome, Chromium, Brave, Edge): the `History`
//! SQLite database. Format reference: Chromium source, `components/history/core/browser`
//! (`url_database`, `visit_database`, `download_database`) and `ui/base/page_transition_types.h`.
//! Both artifacts read the same file, so it is opened twice.
//!
//! The helpers marked `pub(crate)` are shared with the Firefox and Safari parsers.

use crate::common::home::user_from_path;
use crate::macos::plist_util::or_warn;
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use rusqlite::Row;
use serde::Serialize;
use std::borrow::Cow;

const WEBKIT_TO_UNIX_SECS: i64 = 11_644_473_600;

pub const HISTORY: Artifact = Artifact::new(
    "chromium-history",
    "Chrome, Chromium, Brave and Edge browsing history",
    Category::Activity,
    ANY_OS,
    &[
        "home/*/.config/google-chrome/*/History",
        "home/*/.config/chromium/*/History",
        "home/*/.config/BraveSoftware/Brave-Browser/*/History",
        "home/*/.config/microsoft-edge/*/History",
        "root/.config/google-chrome/*/History",
        "root/.config/chromium/*/History",
        "root/.config/BraveSoftware/Brave-Browser/*/History",
        "root/.config/microsoft-edge/*/History",
        "home/*/snap/chromium/common/chromium/*/History",
        "Users/*/Library/Application Support/Google/Chrome/*/History",
        "Users/*/Library/Application Support/Chromium/*/History",
        "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/History",
        "Users/*/Library/Application Support/Microsoft Edge/*/History",
    ],
    parse_history,
)
.companions(WAL);

pub const DOWNLOADS: Artifact = Artifact::new(
    "chromium-downloads",
    "Chrome, Chromium, Brave and Edge downloads",
    Category::Activity,
    ANY_OS,
    HISTORY.paths,
    parse_downloads,
)
.companions(WAL);

const WAL: &[&str] = &[
    "home/*/.config/google-chrome/*/History-wal",
    "home/*/.config/chromium/*/History-wal",
    "home/*/.config/BraveSoftware/Brave-Browser/*/History-wal",
    "home/*/.config/microsoft-edge/*/History-wal",
    "root/.config/google-chrome/*/History-wal",
    "root/.config/chromium/*/History-wal",
    "root/.config/BraveSoftware/Brave-Browser/*/History-wal",
    "root/.config/microsoft-edge/*/History-wal",
    "home/*/snap/chromium/common/chromium/*/History-wal",
    "Users/*/Library/Application Support/Google/Chrome/*/History-wal",
    "Users/*/Library/Application Support/Chromium/*/History-wal",
    "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/History-wal",
    "Users/*/Library/Application Support/Microsoft Edge/*/History-wal",
];

// ---- helpers shared with firefox.rs and safari.rs ----

/// Cuts a timeline message to about 300 characters, on a character boundary.
pub(crate) fn cap(mut message: String) -> String {
    if let Some((end, _)) = message.char_indices().nth(300) {
        message.truncate(end);
        message.push_str("...");
    }
    message
}

pub(crate) fn visit_message(user: &str, url: Option<&str>, title: Option<&str>) -> String {
    let mut message = format!("{user} visited {}", url.unwrap_or("(unknown URL)"));
    if let Some(title) = title.filter(|t| !t.is_empty()) {
        message.push_str(&format!(" ({title})"));
    }
    cap(message)
}

pub(crate) fn download_message(user: &str, url: Option<&str>, path: Option<&str>) -> String {
    cap(format!("{user} downloaded {} to {}", url.unwrap_or("(unknown URL)"), path.unwrap_or("(unknown path)")))
}

// ---- Chromium ----

/// The browser, from the profile root in the path.
fn browser_of(path: &str) -> &'static str {
    if path.contains("/google-chrome/") || path.contains("/Google/Chrome/") {
        "chrome"
    } else if path.contains("/BraveSoftware/") {
        "brave"
    } else if path.contains("/microsoft-edge/") || path.contains("/Microsoft Edge/") {
        "edge"
    } else {
        "chromium"
    }
}

/// The profile directory name (`Default`, `Profile 1`).
pub(crate) fn profile_of(path: &str) -> &str {
    let mut parts = path.rsplit('/');
    parts.next();
    parts.next().unwrap_or_default()
}

/// Chromium time (microseconds since 1601) to Unix; `None` when it does not fit 1677-2262.
fn webkit_time(micros: i64) -> Option<Timestamp> {
    let unix = micros.checked_sub(WEBKIT_TO_UNIX_SECS * 1_000_000)?;
    Timestamp::checked(
        unix.div_euclid(1_000_000),
        unix.rem_euclid(1_000_000) as u32 * 1000,
        Precision::Micros,
        Basis::Recorded,
    )
}

/// A column holding a webkit time; 0 and NULL mean unset.
fn webkit_at(sink: &mut Sink, row: &Row, i: usize, what: &str) -> Option<Timestamp> {
    or_warn(sink, what, int_at(row, i).filter(|&m| m > 0), webkit_time)
}

fn transition_name(transition: Option<i64>) -> Option<Cow<'static, str>> {
    let core = transition? & 0xff;
    Some(Cow::Borrowed(match core {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

#[derive(Serialize)]
struct Visit<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    url: Option<String>,
    title: Option<String>,
    visit_count: Option<i64>,
    typed_count: Option<i64>,
    transition: Option<Cow<'static, str>>,
    /// The whole transition value: the low byte is the type, the rest are qualifier bits.
    transition_raw: Option<i64>,
    from_visit: Option<i64>,
    visit_duration_secs: Option<f64>,
}

impl Record for Visit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "url_visited", visit_message(self.user, self.url.as_deref(), self.title.as_deref())))
            .into_iter()
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["urls", "visits"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT v.visit_time, u.url, u.title, u.visit_count, u.typed_count, v.transition, v.from_visit, \
             v.visit_duration FROM visits v LEFT JOIN {} u ON u.id = v.url ORDER BY v.visit_time, v.id",
            unique_rows("urls", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = webkit_at(sink, row, 0, "visit_time");
        sink.emit(
            Loc::None,
            &Visit {
                time,
                user,
                browser,
                profile,
                url: text_at(row, 1),
                title: text_at(row, 2),
                visit_count: int_at(row, 3),
                typed_count: int_at(row, 4),
                transition: transition_name(int_at(row, 5)),
                transition_raw: int_at(row, 5),
                from_visit: int_at(row, 6),
                visit_duration_secs: int_at(row, 7).map(|us| us as f64 / 1e6),
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
    browser: &'static str,
    profile: &'a str,
    target_path: Option<String>,
    url: Option<String>,
    referrer: Option<String>,
    tab_url: Option<String>,
    received_bytes: Option<i64>,
    total_bytes: Option<i64>,
    state: Option<Cow<'static, str>>,
    danger_type: Option<i64>,
    opened: Option<bool>,
    mime_type: Option<String>,
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

fn download_state(state: Option<i64>) -> Option<Cow<'static, str>> {
    Some(Cow::Borrowed(match state? {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        // Chromium's `DownloadState::BUG_140687`: a retired value that old databases still hold.
        3 => "bug_140687",
        4 => "interrupted",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

fn parse_downloads(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["downloads", "downloads_url_chains"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(
            "SELECT d.start_time, d.end_time, d.target_path, \
             (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1), \
             d.referrer, d.tab_url, d.received_bytes, d.total_bytes, d.state, d.danger_type, d.opened, d.mime_type \
             FROM downloads d ORDER BY d.start_time, d.id",
        )
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let (time, end_time) = (webkit_at(sink, row, 0, "start_time"), webkit_at(sink, row, 1, "end_time"));
        sink.emit(
            Loc::None,
            &Download {
                time,
                end_time,
                user,
                browser,
                profile,
                target_path: text_at(row, 2),
                url: text_at(row, 3),
                referrer: text_at(row, 4),
                tab_url: text_at(row, 5),
                received_bytes: int_at(row, 6),
                total_bytes: int_at(row, 7),
                state: download_state(int_at(row, 8)),
                danger_type: int_at(row, 9),
                opened: int_at(row, 10).map(|n| n != 0),
                mime_type: text_at(row, 11),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const PATH: &str = "home/alice/.config/google-chrome/Default/History";

    #[test]
    fn parses_history() {
        insta::assert_snapshot!(run(&HISTORY, PATH, &fixture("chromium-history/History"), 0));
    }

    /// `n` visits of one URL, and a `urls` table that lists that URL's id `n` times.
    fn duplicate_ids(n: usize) -> Vec<u8> {
        crate::sqlite::database_bytes(&format!(
            "CREATE TABLE urls(id INTEGER, url TEXT, title TEXT, visit_count, typed_count);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit, transition, visit_duration);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < {n})
             INSERT INTO urls SELECT 1, 'http://x/', 't', 1, 0 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < {n})
             INSERT INTO visits(url, visit_time, transition) SELECT 1, 13300000000000000, 0 FROM c;"
        ))
    }

    #[test]
    fn duplicate_url_ids_do_not_multiply_rows() {
        let out = run(&HISTORY, PATH, &duplicate_ids(300), 0);
        assert_eq!(out.matches("\"url\":").count(), 300, "one row per visit");
    }

    #[test]
    fn generated_columns_are_refused() {
        // A virtual generated column is evaluated on every read: 20 MB of text per row.
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY, title TEXT, visit_count, typed_count,
               url TEXT GENERATED ALWAYS AS (printf('%.*c', 20000000, 'x')) VIRTUAL);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit, transition, visit_duration);
             INSERT INTO urls(id,title) VALUES (1,'t');
             INSERT INTO visits(url, visit_time) VALUES (1,13300000000000000),(1,13300000000000001),(1,13300000000000002);",
        );
        let out = run(&HISTORY, PATH, &db, 0);
        assert!(out.contains("--- failed") && out.len() < 10_000, "{}", out.len());
    }

    #[test]
    fn parses_downloads() {
        insta::assert_snapshot!(run(
            &DOWNLOADS,
            "Users/sam/Library/Application Support/Microsoft Edge/Profile 1/History",
            &fixture("chromium-history/History"),
            0
        ));
    }

    #[test]
    fn download_states_and_transition_bits() {
        let name = |n| download_state(Some(n)).unwrap().into_owned();
        assert_eq!([name(1), name(3), name(4), name(9)], ["complete", "bug_140687", "interrupted", "unknown(9)"]);
        // The qualifier bits above the low byte survive in transition_raw.
        let out = run(&HISTORY, PATH, &fixture("chromium-history/History"), 0);
        assert!(out.contains("\"transition_raw\":"), "{out}");
        assert_eq!(transition_name(Some(0x8000_0001)).as_deref(), Some("typed"));
    }

    #[test]
    fn reads_the_wal() {
        let main = fixture("chromium-history/wal/History");
        let wal = fixture("chromium-history/wal/History-wal");
        let without = run(&HISTORY, PATH, &main, 0);
        assert!(!without.contains("wal-only"), "the main file must not hold the WAL visit");
        let wal_path = format!("{PATH}-wal");
        let with = run_on_host(&HISTORY, &[(PATH, &main), (&wal_path, &wal)], PATH, 0);
        assert!(with.contains("Only In WAL"), "{with}");
    }

    #[test]
    fn skips_non_databases_and_other_databases() {
        for artifact in [&HISTORY, &DOWNLOADS] {
            assert!(run(artifact, PATH, b"just some text\n", 0).contains("--- skipped"));
            assert!(run(artifact, PATH, b"", 0).contains("--- skipped"));
            let places = fixture("firefox-history/places.sqlite");
            assert!(run(artifact, PATH, &places, 0).contains("--- skipped: no "));
        }
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("chromium-history/History");
        for artifact in [&HISTORY, &DOWNLOADS] {
            for len in (0..data.len()).step_by(8192) {
                run(artifact, PATH, &data[..len], 0);
            }
            let mut seed = 12345u32;
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

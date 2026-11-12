//! Download history kept by LaunchServices: `com.apple.LaunchServices.QuarantineEventsV2`, an
//! SQLite database with one `LSQuarantineEvent` row per quarantined download. Columns as
//! documented in public macOS forensics write-ups (SANS, "Quarantine events"); timestamps are
//! Mac absolute time (seconds since 2001-01-01 UTC).

use super::plist_util::{mac_time, or_warn};
use super::tcc::select_columns;
use crate::common::home::user_from_path;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "quarantine-events",
    "Files downloaded and quarantined (LaunchServices)",
    Category::Security,
    MACOS,
    &["Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"],
    parse,
)
.companions(&["Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2-wal"]);

#[derive(Serialize)]
struct Download<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    event_id: Option<String>,
    agent_bundle_id: Option<String>,
    agent_name: Option<String>,
    url: Option<String>,
    origin_url: Option<String>,
    origin_title: Option<String>,
    sender_name: Option<String>,
    sender_address: Option<String>,
    type_number: Option<i64>,
}

impl Record for Download<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} downloaded {}",
            self.agent_name.as_deref().or(self.agent_bundle_id.as_deref()).unwrap_or("unknown agent"),
            self.url.as_deref().unwrap_or("unknown URL")
        );
        self.time.map(|ts| Event::new(ts, "file_quarantined", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["LSQuarantineEvent"])?;
    let names = [
        "LSQuarantineTimeStamp",
        "LSQuarantineEventIdentifier",
        "LSQuarantineAgentBundleIdentifier",
        "LSQuarantineAgentName",
        "LSQuarantineDataURLString",
        "LSQuarantineOriginURLString",
        "LSQuarantineOriginTitle",
        "LSQuarantineSenderName",
        "LSQuarantineSenderAddress",
        "LSQuarantineTypeNumber",
    ];
    let list = select_columns(&db, "LSQuarantineEvent", &names)?;
    let sql = format!("SELECT {} FROM LSQuarantineEvent ORDER BY rowid", list.join(", "));
    let user = user_from_path(input.path);
    let mut statement = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = or_warn(sink, "LSQuarantineTimeStamp", real_at(row, 0), mac_time);
        sink.emit(
            Loc::None,
            &Download {
                time,
                user,
                event_id: text_at(row, 1),
                agent_bundle_id: text_at(row, 2),
                agent_name: text_at(row, 3),
                url: text_at(row, 4),
                origin_url: text_at(row, 5),
                origin_title: text_at(row, 6),
                sender_name: text_at(row, 7),
                sender_address: text_at(row, 8),
                type_number: int_at(row, 9),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";

    #[test]
    fn parses_events() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("quarantine-events/QuarantineEventsV2"), 0));
    }

    #[test]
    fn other_inputs_are_skipped() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: not an SQLite database"));
        let other = fixture("tcc/not-tcc.db");
        assert!(run(&ARTIFACT, PATH, &other, 0).contains("skipped: no LSQuarantineEvent table"));
    }

    #[test]
    fn absurd_times_are_dropped_with_a_warning() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL);
             INSERT INTO LSQuarantineEvent VALUES ('a', 1e300);
             INSERT INTO LSQuarantineEvent VALUES ('b', 9223372036854775807);",
        );
        let out = run(&ARTIFACT, PATH, &db, 0);
        assert_eq!(out.matches("\"time\":null").count(), 2, "{out}");
        assert_eq!(out.matches("is not a valid time").count(), 2, "{out}");
        assert!(!out.contains("2262"), "{out}");
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("quarantine-events/QuarantineEventsV2");
        for len in (0..data.len()).step_by(997) {
            run(&ARTIFACT, PATH, &data[..len], 0);
        }
        let mut seed = 11u32;
        for _ in 0..20 {
            let mut copy = data.clone();
            for _ in 0..8 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let at = (seed >> 8) as usize % copy.len();
                copy[at] ^= (seed & 0xff) as u8 | 1;
            }
            run(&ARTIFACT, PATH, &copy, 0);
        }
    }
}

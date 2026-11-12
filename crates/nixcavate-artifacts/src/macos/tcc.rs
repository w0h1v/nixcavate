//! TCC privacy permissions: `TCC.db`, table `access`. The column layout is the one documented
//! in public TCC research (Rainforest QA, "A deep dive into macOS TCC.db"; Apple's `tccd`
//! behaviour as described in the Apple Platform Security guide). Modern systems (11+) store
//! `auth_value`/`auth_reason`; 10.14-10.15 stored `allowed`/`prompt_count`. The columns present
//! are read from `PRAGMA table_info`, so both layouts parse.
//!
//! `select_columns` is shared with the other SQLite-based macOS artifacts.

use super::plist_util::or_warn;
use crate::common::home::user_from_path;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at, Database};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "tcc",
    "macOS privacy permission grants (TCC)",
    Category::Security,
    MACOS,
    &["Library/Application Support/com.apple.TCC/TCC.db", "Users/*/Library/Application Support/com.apple.TCC/TCC.db"],
    parse,
)
.companions(&[
    "Library/Application Support/com.apple.TCC/TCC.db-wal",
    "Users/*/Library/Application Support/com.apple.TCC/TCC.db-wal",
]);

/// The select expression for each of `names`: `"name"` when the table has that column and
/// `NULL` when it does not, so one query serves every schema version. Shared by the SQLite
/// macOS artifacts. Only names from the parser's own fixed lists are passed in; names found in
/// the evidence are never put into SQL.
pub(super) fn select_columns(db: &Database, table: &str, names: &[&str]) -> Result<Vec<String>> {
    let mut statement = db.conn.prepare(&format!("PRAGMA table_info(\"{table}\")")).map_err(sql_error)?;
    let present: Vec<String> =
        statement.query_map([], |row| row.get::<_, String>(1)).map_err(sql_error)?.filter_map(|n| n.ok()).collect();
    Ok(names
        .iter()
        .map(|name| if present.iter().any(|c| c == name) { format!("\"{name}\"") } else { "NULL".to_string() })
        .collect())
}

#[derive(Serialize)]
struct Grant<'a> {
    user: &'a str,
    service: String,
    client: String,
    client_type: String,
    auth_value: String,
    auth_reason: Option<String>,
    indirect_object: Option<String>,
    time: Option<Timestamp>,
    flags: Option<i64>,
}

impl Record for Grant<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} {} for {}", self.client, self.auth_value, self.service);
        self.time.map(|ts| Event::new(ts, "tcc_changed", message)).into_iter()
    }
}

fn client_type(value: Option<i64>) -> String {
    match value {
        Some(0) => "bundle_id".into(),
        Some(1) => "absolute_path".into(),
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn auth_value(value: Option<i64>, legacy: bool) -> String {
    match (value, legacy) {
        (Some(0), _) => "denied".into(),
        (Some(1), false) => "unknown".into(),
        (Some(1), true) | (Some(2), false) => "allowed".into(),
        (Some(3), false) => "limited".into(),
        (Some(n), _) => n.to_string(),
        (None, _) => String::new(),
    }
}

fn auth_reason(value: i64) -> String {
    const NAMES: [&str; 13] = [
        "error",
        "user_consent",
        "user_set",
        "system_set",
        "service_policy",
        "mdm_policy",
        "override_policy",
        "missing_usage_string",
        "prompt_timeout",
        "preflight_unknown",
        "entitled",
        "app_type_policy",
        "prompt_cancel",
    ];
    usize::try_from(value).ok().and_then(|i| NAMES.get(i)).map_or_else(|| value.to_string(), |n| (*n).to_string())
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["access"])?;
    let names = [
        "service",
        "client",
        "client_type",
        "auth_value",
        "allowed",
        "auth_reason",
        "indirect_object_identifier",
        "last_modified",
        "flags",
    ];
    let columns = select_columns(&db, "access", &names)?;
    let legacy = columns[3] == "NULL";
    let auth_column = if legacy { &columns[4] } else { &columns[3] };
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {}, {}, {} FROM access ORDER BY rowid",
        columns[0], columns[1], columns[2], auth_column, columns[5], columns[6], columns[7], columns[8],
    );
    let user = user_from_path(input.path);
    let mut statement = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = or_warn(sink, "last_modified", real_at(row, 6), |secs| {
            let precision = if secs.fract() == 0.0 { Precision::Seconds } else { Precision::Micros };
            Timestamp::from_secs_f64(secs, precision, Basis::Recorded)
        });
        sink.emit(
            Loc::None,
            &Grant {
                user,
                service: text_at(row, 0).unwrap_or_default(),
                client: text_at(row, 1).unwrap_or_default(),
                client_type: client_type(int_at(row, 2)),
                auth_value: auth_value(int_at(row, 3), legacy),
                auth_reason: int_at(row, 4).map(auth_reason),
                indirect_object: text_at(row, 5),
                time,
                flags: int_at(row, 7),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Users/alice/Library/Application Support/com.apple.TCC/TCC.db";

    #[test]
    fn parses_modern_schema() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("tcc/TCC-modern.db"), 0));
    }

    #[test]
    fn parses_legacy_schema_for_the_system_database() {
        let path = "Library/Application Support/com.apple.TCC/TCC.db";
        insta::assert_snapshot!(run(&ARTIFACT, path, &fixture("tcc/TCC-legacy.db"), 0));
    }

    #[test]
    fn other_inputs_are_skipped() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: not an SQLite database"));
        assert!(run(&ARTIFACT, PATH, b"text", 0).contains("skipped: not an SQLite database"));
        assert!(run(&ARTIFACT, PATH, &fixture("tcc/not-tcc.db"), 0).contains("skipped: no access table"));
    }

    #[test]
    fn absurd_times_are_dropped_with_a_warning() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, last_modified);
             INSERT INTO access VALUES ('kTCCServiceCamera', 'a', 0, 2, 1e300);
             INSERT INTO access VALUES ('kTCCServiceCamera', 'b', 0, 2, 9223372036854775807);",
        );
        let out = run(&ARTIFACT, PATH, &db, 0);
        assert_eq!(out.matches("\"time\":null").count(), 2, "{out}");
        assert_eq!(out.matches("last_modified").count(), 2, "{out}");
        assert!(out.contains("is not a valid time"), "{out}");
        assert!(!out.contains("2262"), "{out}");
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("tcc/TCC-modern.db");
        for len in (0..data.len()).step_by(997) {
            run(&ARTIFACT, PATH, &data[..len], 0);
        }
        let mut seed = 7u32;
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

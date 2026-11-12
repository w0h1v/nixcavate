//! `knowledgeC.db`: the CoreDuet "knowledge" store (app usage, focus, lock state, Safari
//! history, notifications, now-playing). A Core Data SQLite database; one `ZOBJECT` row is one
//! event of a stream (`ZSTREAMNAME`).
//!
//! References: Sarah Edwards, "Knowledge is Power! Using the macOS/iOS knowledgeC.db Database
//! to Determine Precise User and Device Usage" (mac4n6.com, 2018) for the table layout and the
//! stream names. Times are Mac absolute time (seconds since 2001-01-01 UTC, REAL).
//!
//! Validated only against a synthetic database built from that description
//! (`test_files/knowledgec/generate.py`). Assumptions that were not checked against real files:
//! `ZSOURCE.ZBUNDLEID` / `ZDEVICEID` hold the source, `ZOBJECT.ZSTRUCTUREDMETADATA` and
//! `ZOBJECT.ZSOURCE` are `Z_PK` foreign keys, and metadata columns start with `Z_DK` and carry
//! a `...METADATAKEY__` infix. The metadata columns differ between macOS versions, so they are
//! discovered from the schema instead of being listed here.

use super::plist_util::{mac_time, or_warn};
use crate::common::home::user_from_path;
use crate::sqlite::{open_with_tables, real_at, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

pub const ARTIFACT: Artifact = Artifact::new(
    "knowledgec",
    "macOS KnowledgeC activity store",
    Category::Activity,
    MACOS,
    &["private/var/db/CoreDuet/Knowledge/knowledgeC.db", "Users/*/Library/Application Support/Knowledge/knowledgeC.db"],
    parse,
)
.companions(&[
    "private/var/db/CoreDuet/Knowledge/knowledgeC.db-wal",
    "Users/*/Library/Application Support/Knowledge/knowledgeC.db-wal",
]);

#[derive(Serialize)]
struct Object<'a> {
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    created_time: Option<Timestamp>,
    /// End minus start; negative when the store holds an end before the start.
    duration_secs: Option<f64>,
    stream: String,
    value: String,
    source_bundle_id: String,
    device_id: String,
    gmt_offset_secs: Option<i64>,
    user: &'a str,
    metadata: BTreeMap<String, Value>,
}

impl Record for Object<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "activity", format!("{} {}", self.stream, self.value))).into_iter()
    }
}

fn columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).map_err(sql_error)?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1)).map_err(sql_error)?;
    Ok(names.filter_map(|n| n.ok()).collect())
}

fn json(value: ValueRef) -> Option<Value> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.into()),
        ValueRef::Real(r) => serde_json::Number::from_f64(r).map(Value::Number),
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned().into()),
        ValueRef::Blob(b) => Some(format!("<blob {} bytes>", b.len()).into()),
    }
}

/// `Z_DKSAFARIHISTORYMETADATAKEY__TITLE` becomes `TITLE`.
fn short_name(column: &str) -> &str {
    column.split_once("METADATAKEY__").map_or_else(|| column.trim_start_matches("Z_DK"), |(_, rest)| rest)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["ZOBJECT"])?;
    db.refuse_generated_columns(&["ZSOURCE", "ZSTRUCTUREDMETADATA"])?;
    let object = columns(&db.conn, "ZOBJECT")?;
    if !object.contains("ZSTREAMNAME") || !object.contains("ZSTARTDATE") {
        return Err(Error::skipped("ZOBJECT has no ZSTREAMNAME/ZSTARTDATE: not a KnowledgeC database"));
    }
    let col = |name: &str| if object.contains(name) { format!("o.{name}") } else { "NULL".to_string() };

    let source = db.has_table("ZSOURCE") && object.contains("ZSOURCE");
    let source_cols = if source { columns(&db.conn, "ZSOURCE")? } else { HashSet::new() };
    let src = |name: &str| if source_cols.contains(name) { format!("s.{name}") } else { "NULL".to_string() };

    let meta = db.has_table("ZSTRUCTUREDMETADATA") && object.contains("ZSTRUCTUREDMETADATA");
    let mut meta_cols: Vec<String> = Vec::new();
    if meta {
        meta_cols = columns(&db.conn, "ZSTRUCTUREDMETADATA")?.into_iter().filter(|c| c.starts_with("Z_DK")).collect();
        meta_cols.sort();
    }

    let mut select = vec![
        col("ZSTARTDATE"),
        col("ZENDDATE"),
        col("ZCREATIONDATE"),
        col("ZSTREAMNAME"),
        col("ZVALUESTRING"),
        col("ZVALUEINTEGER"),
        col("ZVALUEDOUBLE"),
        col("ZSECONDSFROMGMT"),
        src("ZBUNDLEID"),
        src("ZDEVICEID"),
    ];
    let fixed = select.len();
    select.extend(meta_cols.iter().map(|c| format!("m.\"{}\"", c.replace('"', "\"\""))));
    let mut sql = format!("SELECT {} FROM ZOBJECT o", select.join(", "));
    if source {
        sql.push_str(&format!(" LEFT JOIN {} s ON o.ZSOURCE = s.Z_PK", unique_rows("ZSOURCE", "Z_PK")));
    }
    if meta {
        let table = unique_rows("ZSTRUCTUREDMETADATA", "Z_PK");
        sql.push_str(&format!(" LEFT JOIN {table} m ON o.ZSTRUCTUREDMETADATA = m.Z_PK"));
    }
    sql.push_str(" ORDER BY o.ZSTARTDATE, o.rowid");

    let user = user_from_path(input.path);
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(e) => {
                sink.warn(format!("stopped reading ZOBJECT: {e}"));
                break;
            }
        };
        let get = |i: usize| row.get_ref(i).unwrap_or(ValueRef::Null);
        let (start, end) = (real_at(row, 0), real_at(row, 1));
        let value = [4, 5, 6].into_iter().find_map(|i| text_at(row, i)).unwrap_or_default();
        let mut metadata = BTreeMap::new();
        for (i, column) in meta_cols.iter().enumerate() {
            let Some(v) = json(get(fixed + i)) else { continue };
            let name = short_name(column);
            // Two families filled in one row would collide; keep the full name then.
            let name = if metadata.contains_key(name) { column.as_str() } else { name };
            metadata.insert(name.to_string(), v);
        }
        let time = or_warn(sink, "ZSTARTDATE", start, mac_time);
        let end_time = or_warn(sink, "ZENDDATE", end, mac_time);
        let created_time = or_warn(sink, "ZCREATIONDATE", real_at(row, 2), mac_time);
        sink.emit(
            Loc::None,
            &Object {
                time,
                end_time,
                created_time,
                duration_secs: start.zip(end).map(|(s, e)| e - s),
                stream: text_at(row, 3).unwrap_or_default(),
                value,
                source_bundle_id: text_at(row, 8).unwrap_or_default(),
                device_id: text_at(row, 9).unwrap_or_default(),
                gmt_offset_secs: real_at(row, 7).map(|v| v as i64),
                user,
                metadata,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const USER_PATH: &str = "Users/alice/Library/Application Support/Knowledge/knowledgeC.db";

    #[test]
    fn parses_synthetic_user_database() {
        insta::assert_snapshot!(run(&ARTIFACT, USER_PATH, &fixture("knowledgec/knowledgeC.db"), 0));
    }

    #[test]
    fn system_database_has_no_user() {
        let out =
            run(&ARTIFACT, "private/var/db/CoreDuet/Knowledge/knowledgeC.db", &fixture("knowledgec/knowledgeC.db"), 0);
        assert!(out.contains("\"user\":\"\""), "{out}");
    }

    #[test]
    fn non_sqlite_and_wrong_schema_are_skipped() {
        assert!(run(&ARTIFACT, USER_PATH, b"hello, not a database", 0).contains("--- skipped"));
        assert!(run(&ARTIFACT, USER_PATH, b"", 0).contains("--- skipped"));

        let db = |sql: &str| {
            let path = std::env::temp_dir().join(format!("nixcavate-kc-{}-{}.db", std::process::id(), sql.len()));
            let _ = std::fs::remove_file(&path);
            Connection::open(&path).unwrap().execute_batch(sql).unwrap();
            let data = std::fs::read(&path).unwrap();
            let _ = std::fs::remove_file(&path);
            data
        };
        let out = run(&ARTIFACT, USER_PATH, &db("CREATE TABLE other (a);"), 0);
        assert!(out.contains("--- skipped: no ZOBJECT"), "{out}");
        let out = run(&ARTIFACT, USER_PATH, &db("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZFOO);"), 0);
        assert!(out.contains("--- skipped: ZOBJECT has no"), "{out}");
    }

    #[test]
    fn absurd_mac_times_are_dropped_with_a_warning() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME, ZSTARTDATE, ZENDDATE);
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 5.0e10, 0.0);",
        );
        let out = run(&ARTIFACT, USER_PATH, &db, 0);
        assert!(out.contains("\"time\":null") && out.contains("2001-01-01T00:00:00Z"), "{out}");
        assert!(out.contains("ZSTARTDATE 50000000000 is not a valid time"), "{out}");
    }

    #[test]
    fn duplicate_keys_do_not_multiply_rows() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME, ZSTARTDATE, ZSOURCE);
             CREATE TABLE ZSOURCE (Z_PK INTEGER, ZBUNDLEID);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO ZSOURCE SELECT 1, 'com.x' FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO ZOBJECT(ZSTREAMNAME, ZSTARTDATE, ZSOURCE) SELECT '/app/inFocus', 1.0, 1 FROM c;",
        );
        assert_eq!(run(&ARTIFACT, USER_PATH, &db, 0).matches("\"stream\":").count(), 200);
    }

    /// Needs real files, which must not live in the repository. Place copies under
    /// the directory named by `NIXCAVATE_ACTIVITY_CORPUS` (any `knowledgeC.db`) and run
    /// `cargo test -p nixcavate-artifacts -- --ignored real_corpus`.
    #[test]
    #[ignore]
    fn real_corpus_knowledgec() {
        let Ok(dir) = std::fs::read_dir(std::env::var("NIXCAVATE_ACTIVITY_CORPUS").unwrap_or_default()) else { return };
        for entry in dir.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("knowledgeC")) {
            let Ok(data) = std::fs::read(entry.path()) else { continue };
            let out = run(&ARTIFACT, USER_PATH, &data, 0);
            assert!(
                !out.contains("--- failed"),
                "{}: {}",
                entry.path().display(),
                &out[out.len().saturating_sub(300)..]
            );
        }
    }
}

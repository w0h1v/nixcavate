//! The power log: `CurrentPowerlog.PLSQL` and its `powerlog_*.PLSQL.gz` archives. A SQLite
//! database with one `PL<Agent>_<Kind>_<Name>` table per metric. Only the tables that show what
//! ran and what the machine did are read (applications, process network use, sleep and wake,
//! display, battery, camera and audio, Wi-Fi, Bluetooth).
//!
//! Reference: Sarah Edwards' APOLLO (module list, and the correction of each row's `timestamp`
//! by the nearest earlier `PLStorageOperator_EventForward_TimeOffset` row, `timestamp +
//! system`). Table names are matched by lowercase prefix and every column the table has is
//! kept in `detail`, because the column sets differ between macOS versions; no column list
//! here is claimed to match every version.
//!
//! Synthetic only: no real power log was available. The doubts are the exact table and column
//! names per macOS version and the sign and meaning of the time-offset correction.

use super::util::{cell, clip, column_names, pick, quote, table_names, with_data};
use crate::sqlite::{open, real_at, sql_error};
use crate::text::decompressed;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "powerlog",
    "macOS power log (application, power, network and device activity)",
    Category::Activity,
    MACOS,
    &[
        "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL",
        "private/var/db/powerlog/Library/BatteryLife/Archives/powerlog_*.PLSQL.gz",
        "private/var/db/powerlog/Library/BatteryLife/Archives/powerlog_*.PLSQL",
    ],
    parse,
)
.companions(&["private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL-wal"]);

/// Table-name prefixes (lowercase) in order of precedence, and the stream each gives.
const STREAMS: &[(&str, &str)] = &[
    ("plapplicationagent_eventnone_allapps", "installed_app"),
    ("plapptimeservice_", "app_time"),
    ("plapplicationagent_", "app_state"),
    ("plprocessnetworkagent_", "process_network"),
    ("plsleepwakeagent_", "sleep_wake"),
    ("pldisplayagent_", "display"),
    ("plbatteryagent_", "battery"),
    ("plavcagent_", "camera"),
    ("plcameraagent_", "camera"),
    ("plaudioagent_", "audio"),
    ("plwifiagent_", "wifi"),
    ("plbluetoothagent_", "bluetooth"),
];
const OFFSET_TABLE: &str = "plstorageoperator_eventforward_timeoffset";
/// What names the thing a row is about, in order of preference.
const SUBJECTS: &[&str] = &[
    "BundleID",
    "BundleIdentifier",
    "ProcessName",
    "AppName",
    "Name",
    "BundleName",
    "Executable",
    "SSID",
    "DeviceName",
];
const MAX_COLUMNS: usize = 40;
const MAX_OFFSETS: usize = 1 << 20;

#[derive(Serialize)]
struct Entry {
    table: String,
    kind: &'static str,
    /// The row's `timestamp` plus the time offset in force, when one applies.
    time: Option<Timestamp>,
    /// The `timestamp` column as stored.
    raw_time: Option<Timestamp>,
    time_offset_secs: Option<f64>,
    subject: Option<String>,
    detail: BTreeMap<String, Value>,
}

impl Record for Entry {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = if self.kind == "installed_app" { "software_installed" } else { "activity" };
        let what = self.subject.clone().unwrap_or_else(|| {
            let fields: Vec<String> = self.detail.iter().take(3).map(|(k, v)| format!("{k}={v}")).collect();
            fields.join(" ")
        });
        let message = format!("power log {}: {what}", self.kind);
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

fn stream(table: &str) -> Option<&'static str> {
    let lower = table.to_ascii_lowercase();
    STREAMS.iter().find(|(prefix, _)| lower.starts_with(prefix)).map(|&(_, kind)| kind)
}

fn time(secs: f64) -> Option<Timestamp> {
    let precision = if secs.fract() == 0.0 { Precision::Seconds } else { Precision::Micros };
    Timestamp::from_secs_f64(secs, precision, Basis::Recorded)
}

/// `(timestamp, offset)` pairs sorted by timestamp.
fn offsets(db: &crate::sqlite::Database, tables: &[String], sink: &mut Sink) -> Vec<(f64, f64)> {
    let Some(name) = tables.iter().find(|t| t.eq_ignore_ascii_case(OFFSET_TABLE)) else { return Vec::new() };
    let load = || -> Result<Vec<(f64, f64)>> {
        let mut stmt = db
            .conn
            .prepare(&format!("SELECT timestamp, system FROM {} ORDER BY timestamp LIMIT {MAX_OFFSETS}", quote(name)))
            .map_err(sql_error)?;
        let mut rows = stmt.query([]).map_err(sql_error)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(sql_error)? {
            if let (Some(t), Some(s)) = (real_at(row, 0), real_at(row, 1)) {
                if t.is_finite() && s.is_finite() {
                    out.push((t, s));
                }
            }
        }
        Ok(out)
    };
    load().unwrap_or_else(|e| {
        sink.warn(format!("time offsets not read ({e}); times are uncorrected"));
        Vec::new()
    })
}

/// The offset of the last row at or before `t`.
fn offset_at(offsets: &[(f64, f64)], t: f64) -> Option<f64> {
    let after = offsets.partition_point(|&(at, _)| at <= t);
    after.checked_sub(1).and_then(|i| offsets.get(i)).map(|&(_, s)| s)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    let input = with_data(input, &data);
    let db = open(&input)?;
    let tables = table_names(&db)?;
    let offsets = offsets(&db, &tables, sink);
    let mut any = false;
    for table in tables.iter().filter(|t| !t.eq_ignore_ascii_case(OFFSET_TABLE)) {
        let Some(kind) = stream(table) else { continue };
        any = true;
        if let Err(e) = read_table(&db, table, kind, &offsets, sink) {
            sink.warn(format!("table {table} not read: {e}"));
        }
    }
    if !any {
        return Err(nixcavate_core::Error::skipped("no power log tables (PL*Agent_*)"));
    }
    Ok(())
}

fn read_table(
    db: &crate::sqlite::Database,
    table: &str,
    kind: &'static str,
    offsets: &[(f64, f64)],
    sink: &mut Sink,
) -> Result<()> {
    db.refuse_generated_columns(&[table])?;
    let columns = column_names(db, table)?;
    let Some(stamp) = pick(&columns, &["timestamp"]) else {
        return Err(nixcavate_core::Error::skipped("no timestamp column"));
    };
    let stamp_index = columns.iter().position(|c| c == stamp).unwrap_or(0);
    let subject_names: Vec<usize> = SUBJECTS
        .iter()
        .filter_map(|s| pick(&columns, &[s]))
        .filter_map(|name| columns.iter().position(|c| c == name))
        .collect();
    let mut stmt = db.conn.prepare(&format!("SELECT * FROM {}", quote(table))).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut bad_times = 0u32;
    loop {
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(e) => {
                sink.warn(format!("stopped reading {table}: {e}"));
                break;
            }
        };
        let raw = real_at(row, stamp_index);
        let raw_time = raw.and_then(time);
        let offset = raw.and_then(|t| offset_at(offsets, t));
        let corrected = raw.map(|t| t + offset.unwrap_or(0.0)).and_then(time);
        if raw.is_some() && corrected.is_none() {
            bad_times += 1;
        }
        let mut detail = BTreeMap::new();
        for (i, name) in columns.iter().enumerate().take(MAX_COLUMNS) {
            if i == stamp_index || name.eq_ignore_ascii_case("id") {
                continue;
            }
            if let Some(v) = row.get_ref(i).ok().and_then(cell) {
                detail.insert(name.clone(), v);
            }
        }
        let subject = subject_names.iter().find_map(|&i| match detail.get(&columns[i])? {
            Value::String(s) if !s.is_empty() => Some(clip(s, 200)),
            _ => None,
        });
        sink.emit(
            Loc::None,
            &Entry {
                table: table.to_string(),
                kind,
                time: corrected,
                raw_time,
                time_offset_secs: offset,
                subject,
                detail,
            },
        )?;
    }
    if bad_times > 0 {
        sink.warn(format!("{table}: {bad_times} rows have a timestamp that is not a valid time; left empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::database_bytes;
    use crate::testing::{fixture, run};

    const PATH: &str = "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL";

    #[test]
    fn reads_the_application_and_power_streams() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("powerlog/CurrentPowerlog.PLSQL"), 0));
    }

    #[test]
    fn archives_are_read_compressed() {
        let packed = fixture("powerlog/powerlog_2024_01_01.PLSQL.gz");
        let path = "private/var/db/powerlog/Library/BatteryLife/Archives/powerlog_2024_01_01.PLSQL.gz";
        let out = run(&ARTIFACT, path, &packed, 0);
        assert!(out.contains("com.example.app"), "{out}");
    }

    #[test]
    fn offsets_apply_from_the_nearest_earlier_row() {
        let offsets = [(100.0, 5.0), (200.0, -3.0)];
        assert_eq!(offset_at(&offsets, 50.0), None);
        assert_eq!(offset_at(&offsets, 100.0), Some(5.0));
        assert_eq!(offset_at(&offsets, 199.0), Some(5.0));
        assert_eq!(offset_at(&offsets, 1e9), Some(-3.0));
    }

    #[test]
    fn other_databases_are_skipped() {
        let db = database_bytes("CREATE TABLE t (a);");
        assert!(run(&ARTIFACT, PATH, &db, 0).contains("skipped: no power log tables"));
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped"));
    }

    #[test]
    fn a_table_without_timestamps_is_a_warning() {
        let db = database_bytes("CREATE TABLE PLWifiAgent_EventForward_Wifi (SSID TEXT);");
        assert!(run(&ARTIFACT, PATH, &db, 0).contains("table PLWifiAgent_EventForward_Wifi not read"));
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("powerlog/CurrentPowerlog.PLSQL");
        crate::macos::util::survives_sparse(&ARTIFACT, PATH, &data, 997, 30);
    }
}

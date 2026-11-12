//! Read-only access to SQLite artifacts.
//!
//! The database (and its write-ahead log, when collected) is copied to the scratch directory
//! and opened there. The evidence is never opened by SQLite, so no `-shm` file appears next
//! to it, and rows that are still only in the WAL are visible.

use crate::Input;
use nixcavate_core::{Error, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// An open database copy. The copy is deleted when this is dropped.
pub struct Database {
    /// Declared first so the connection closes before the files are removed.
    pub conn: Connection,
    path: PathBuf,
}

static NEXT_COPY: AtomicU64 = AtomicU64::new(0);

/// Copies the input database to scratch and opens it. The artifact must list `<path>-wal`
/// among its companions for the write-ahead log to be applied.
pub fn open(input: &Input) -> Result<Database> {
    if !input.data.starts_with(b"SQLite format 3\0") {
        return Err(Error::skipped("not an SQLite database"));
    }
    fs::create_dir_all(input.scratch)?;
    let path = input.scratch.join(format!("{}.sqlite", NEXT_COPY.fetch_add(1, Ordering::Relaxed)));
    // `create_new`: never write through a file or link someone else put there.
    let create = |path: &std::path::Path| fs::OpenOptions::new().write(true).create_new(true).open(path);
    create(&path)?.write_all(input.data)?;
    if let Some(wal) = input.host.read(&format!("{}-wal", input.path)) {
        create(&wal_path(&path))?.write_all(&wal)?;
    }
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(sql_error)?;
    // The schema is hostile too: no writes, and no functions or virtual tables from views
    // and triggers stored in the file.
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;").map_err(sql_error)?;
    // No single value larger than 16 MiB: a crafted expression could otherwise build a
    // gigabyte string per row.
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 16 << 20).map_err(sql_error)?;
    Ok(Database { conn, path })
}

fn wal_path(db: &std::path::Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

/// Converts a SQLite error into a format error, for use with `?`.
pub fn sql_error(e: rusqlite::Error) -> Error {
    Error::format(format!("sqlite: {e}"))
}

/// Opens the database and checks that the tables are there. A corrupt file is a format error;
/// a valid database without the tables is skipped. Tables with generated columns are refused.
pub fn open_with_tables(input: &Input, tables: &[&str]) -> Result<Database> {
    let db = open(input)?;
    for table in tables {
        if !db.has_table(table) {
            return Err(Error::skipped(format!("no {table} table")));
        }
    }
    db.refuse_generated_columns(tables)?;
    Ok(db)
}

/// A subquery with one row per distinct `key`, to join on: the schema is hostile, so a key
/// that should be unique may repeat, and a plain join would multiply the rows of the other
/// side. The row kept is the first (lowest rowid) of each key.
pub fn unique_rows(table: &str, key: &str) -> String {
    format!("(SELECT *, min(rowid) FROM {table} GROUP BY {key})")
}

/// Text in column `i`, whatever its declared type; NULL and unreadable values give `None`.
pub fn text_at(row: &Row, i: usize) -> Option<String> {
    match row.get_ref(i).ok()? {
        ValueRef::Text(b) | ValueRef::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Integer(n) => Some(n.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Null => None,
    }
}

pub fn int_at(row: &Row, i: usize) -> Option<i64> {
    match row.get_ref(i).ok()? {
        ValueRef::Integer(n) => Some(n),
        ValueRef::Real(f) => Some(f as i64),
        ValueRef::Text(b) => std::str::from_utf8(b).ok()?.trim().parse().ok(),
        _ => None,
    }
}

pub fn real_at(row: &Row, i: usize) -> Option<f64> {
    match row.get_ref(i).ok()? {
        ValueRef::Integer(n) => Some(n as f64),
        ValueRef::Real(f) => Some(f),
        _ => None,
    }
}

impl Database {
    /// Fails when one of these tables (the ones that exist) has a generated or hidden column.
    /// A virtual generated column is an expression SQLite evaluates on every read, and a
    /// hostile file can make it build hundreds of megabytes per row from a few bytes
    /// (`printf('%.*c', 200000000, 'x')`). Real artifact databases have none. Setting
    /// `SQLITE_LIMIT_LENGTH` would be the direct fix; it needs rusqlite's `limits` feature.
    pub fn refuse_generated_columns(&self, tables: &[&str]) -> Result<()> {
        for table in tables {
            let mut stmt = self
                .conn
                .prepare(&format!("PRAGMA table_xinfo(\"{}\")", table.replace('"', "\"\"")))
                .map_err(sql_error)?;
            let hidden = stmt.query_map([], |row| row.get::<_, i64>(6)).map_err(sql_error)?;
            for flag in hidden {
                if flag.map_err(sql_error)? != 0 {
                    return Err(Error::format(format!(
                        "table {table} has generated columns; refusing to evaluate them"
                    )));
                }
            }
        }
        Ok(())
    }

    /// True when the database has a table of this name.
    pub fn has_table(&self, name: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [name], |_| Ok(()))
            .is_ok()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.path.as_os_str().to_owned();
            name.push(suffix);
            let _ = fs::remove_file(name);
        }
    }
}

/// An SQLite database file built from SQL, for tests.
#[cfg(test)]
pub(crate) fn database_bytes(sql: &str) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!(
        "nixcavate-test-{}-{}.db",
        std::process::id(),
        NEXT_COPY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&path);
    Connection::open(&path).unwrap().execute_batch(sql).unwrap();
    let data = fs::read(&path).unwrap();
    let _ = fs::remove_file(&path);
    data
}

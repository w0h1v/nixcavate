//! Small helpers shared by the SQLite and binary macOS artifacts added with the power log,
//! crash reports and application-metadata parsers.

use crate::sqlite::Database;
use crate::Input;
use nixcavate_core::Result;
use rusqlite::types::ValueRef;
use serde_json::Value;

/// Longest text kept from one database cell or plist string.
pub const CLIP: usize = 512;

/// `text` cut to at most `max` bytes on a character boundary, with `...` marking the cut.
pub fn clip(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// A database cell as JSON: NULL is `None`, blobs are only described (never copied), and long
/// text is clipped.
pub fn cell(value: ValueRef) -> Option<Value> {
    match value {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.into()),
        ValueRef::Real(r) => serde_json::Number::from_f64(r).map(Value::Number),
        ValueRef::Text(t) => Some(clip(&String::from_utf8_lossy(t), CLIP).into()),
        ValueRef::Blob(b) => Some(format!("<blob {} bytes>", b.len()).into()),
    }
}

/// The input with its (possibly compressed) data replaced by `data`, for a parser that opens
/// a database or file stored gzip-compressed (rotated archives).
pub fn with_data<'a>(input: &Input<'a>, data: &'a [u8]) -> Input<'a> {
    Input { data, ..*input }
}

/// The lowercase names of the tables of the database.
pub fn table_names(db: &Database) -> Result<Vec<String>> {
    let mut stmt = db
        .conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .map_err(crate::sqlite::sql_error)?;
    let names = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(crate::sqlite::sql_error)?;
    Ok(names.filter_map(|n| n.ok()).collect())
}

/// `name` as a quoted SQL identifier.
pub fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The names of the columns of `table`.
pub fn column_names(db: &Database, table: &str) -> Result<Vec<String>> {
    let mut stmt =
        db.conn.prepare(&format!("PRAGMA table_info({})", quote(table))).map_err(crate::sqlite::sql_error)?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1)).map_err(crate::sqlite::sql_error)?;
    Ok(names.filter_map(|n| n.ok()).collect())
}

/// The first of `candidates` that is among `columns`, compared without regard to case, as the
/// real column name.
pub fn pick<'a>(columns: &'a [String], candidates: &[&str]) -> Option<&'a str> {
    candidates.iter().find_map(|c| columns.iter().find(|n| n.eq_ignore_ascii_case(c)).map(String::as_str))
}

/// Feeds truncated and byte-flipped copies of a larger fixture (a database) to an artifact:
/// every `step` bytes for truncation and `flips` random mutations. Only a panic fails.
#[cfg(test)]
pub fn survives_sparse(artifact: &crate::Artifact, path: &str, data: &[u8], step: usize, flips: usize) {
    use crate::testing::run;
    for len in (0..data.len()).step_by(step.max(1)) {
        run(artifact, path, &data[..len], 0);
    }
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..flips {
        let mut copy = data.to_vec();
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = (state % copy.len() as u64) as usize;
            copy[at] ^= (state >> 32) as u8 | 1;
        }
        run(artifact, path, &copy, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_respects_characters() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("aéb", 2), "a...");
        assert_eq!(clip("abcdef", 3), "abc...");
    }
}

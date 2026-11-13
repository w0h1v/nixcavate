//! A read-only reader for SQLite 2.x database files. The SMF repository (`etc/svc/repository.db`
//! and its `repository-boot*` backups) is an SQLite **2.1** file, not the SQLite 3 format the
//! `crate::sqlite` helper opens, so it is read here directly.
//!
//! Format, as found in the 2.x B-tree code and checked against real repositories with the
//! `sqlite` shell that ships in `/lib/svc/bin`:
//!
//! * Pages are 1024 bytes. Page 1 holds a 48-byte magic string (`** This file contains an
//!   SQLite 2.1 database **`) and the integer `0xdae37528` written in the file's byte order,
//!   which tells little-endian from big-endian (SPARC). `sqlite_master` is rooted at page 2.
//! * A B-tree page starts with `rightChild: u32`, `firstCell: u16`, `firstFree: u16`. Cells are
//!   chained through `iNext`. A cell is `leftChild: u32`, `nKey: u16`, `iNext: u16`,
//!   `nKeyHi: u8`, `nDataHi: u8`, `nData: u16`, then the first 236 bytes of the key followed by
//!   the data; a longer payload continues in a chain of overflow pages (`next: u32` and 1020
//!   bytes) whose first page number follows the 236 local bytes. Interior pages carry data too,
//!   so a table is read in order: left child, cell, ..., right child.
//! * A table's key is the row id, 4 bytes big-endian with the sign bit flipped. The data is a
//!   record: `N + 1` offsets (1, 2 or 3 bytes each, the narrowest that holds the record's
//!   length), then N NUL-terminated text fields (every value is text). A field with equal
//!   neighbouring offsets, no bytes at all, is NULL.
//!
//! Hostile input: every page number is checked against the file size, a visited set stops
//! cycles, and row and payload sizes are capped.

use std::collections::HashSet;

const PAGE: usize = 1024;
const MAGIC: &[u8] = b"** This file contains an SQLite 2.1 database **\0";
/// How much of a payload is kept in the cell itself.
const LOCAL: usize = 236;
const MAX_PAYLOAD: usize = 4 << 20;
const MAX_PAGES_PER_TABLE: usize = 1 << 20;

#[derive(Debug)]
pub struct Db<'a> {
    data: &'a [u8],
    big: bool,
}

/// One row: its row id and fields, NULL as `None`.
pub struct Row {
    pub id: i64,
    pub fields: Vec<Option<String>>,
}

/// True when `data` starts like an SQLite 2.x file.
pub fn is_sqlite2(data: &[u8]) -> bool {
    data.starts_with(&MAGIC[..40])
}

impl<'a> Db<'a> {
    pub fn open(data: &'a [u8]) -> Result<Db<'a>, String> {
        if !is_sqlite2(data) {
            return Err("not an SQLite 2.x database".into());
        }
        let Some(magic) = data.get(48..52) else { return Err("truncated header".into()) };
        let big = match [magic[0], magic[1], magic[2], magic[3]] {
            [0x28, 0x75, 0xe3, 0xda] => false,
            [0xda, 0xe3, 0x75, 0x28] => true,
            _ => return Err("byte-order marker is wrong".into()),
        };
        if data.len() < 2 * PAGE {
            return Err("truncated: no sqlite_master page".into());
        }
        Ok(Db { data, big })
    }

    fn u32_at(&self, page: &[u8], at: usize) -> Option<u32> {
        let b = page.get(at..at + 4)?;
        let raw = [b[0], b[1], b[2], b[3]];
        Some(if self.big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    }

    fn u16_at(&self, page: &[u8], at: usize) -> Option<usize> {
        let b = page.get(at..at + 2)?;
        let raw = [b[0], b[1]];
        Some(usize::from(if self.big { u16::from_be_bytes(raw) } else { u16::from_le_bytes(raw) }))
    }

    /// The page numbered `n` (1-based), if the file holds it whole.
    fn page(&self, n: u32) -> Option<&'a [u8]> {
        let start = (n as usize).checked_sub(1)?.checked_mul(PAGE)?;
        self.data.get(start..start.checked_add(PAGE)?)
    }

    /// The tables, from `sqlite_master`: (name, root page, `CREATE` statement).
    pub fn tables(&self) -> Result<Vec<(String, u32, String)>, String> {
        let mut tables = Vec::new();
        self.scan(2, |row| {
            if let [Some(kind), Some(name), _, Some(root), sql] = &row.fields[..] {
                if let (true, Ok(root)) = (kind == "table", root.parse()) {
                    tables.push((name.clone(), root, sql.clone().unwrap_or_default()));
                }
            }
            true
        })?;
        Ok(tables)
    }

    /// The root page of a table, by name.
    pub fn root_of(&self, table: &str) -> Result<Option<u32>, String> {
        Ok(self.tables()?.into_iter().find(|(name, _, _)| name == table).map(|(_, root, _)| root))
    }

    /// Calls `f` with every row of the table rooted at `root`, in row id order, until it returns
    /// false. A damaged page ends the scan with an error after the rows before it were delivered.
    pub fn scan(&self, root: u32, mut f: impl FnMut(Row) -> bool) -> Result<(), String> {
        let mut visited = HashSet::new();
        let mut rows = 0usize;
        self.walk(root, &mut visited, &mut rows, 0, &mut f).map(|_| ())
    }

    /// Returns Ok(false) when `f` asked to stop.
    fn walk(
        &self,
        number: u32,
        visited: &mut HashSet<u32>,
        rows: &mut usize,
        depth: usize,
        f: &mut impl FnMut(Row) -> bool,
    ) -> Result<bool, String> {
        if depth > 64 {
            return Err("B-tree is deeper than 64 levels".into());
        }
        if number == 0 {
            return Ok(true);
        }
        if visited.len() >= MAX_PAGES_PER_TABLE || !visited.insert(number) {
            return Err(format!("page {number} is visited twice (a cycle) or the table is too large"));
        }
        let page = self.page(number).ok_or_else(|| format!("page {number} is outside the file"))?;
        let right = self.u32_at(page, 0).ok_or("short page")?;
        let mut cell = self.u16_at(page, 4).ok_or("short page")?;
        let mut seen_cells = 0;
        while cell != 0 {
            seen_cells += 1;
            // A page holds at most (1024 - 8) / 16 cells; more means the chain loops.
            if seen_cells > PAGE / 16 {
                return Err(format!("page {number}: cell chain does not end"));
            }
            let bytes =
                page.get(cell..).ok_or_else(|| format!("page {number}: cell offset {cell} is outside the page"))?;
            let left = self.u32_at(bytes, 0).ok_or("short cell")?;
            let key_len =
                self.u16_at(bytes, 4).ok_or("short cell")? + (usize::from(*bytes.get(8).ok_or("short cell")?) << 16);
            let next = self.u16_at(bytes, 6).ok_or("short cell")?;
            let data_len =
                self.u16_at(bytes, 10).ok_or("short cell")? + (usize::from(*bytes.get(9).ok_or("short cell")?) << 16);
            if !self.walk(left, visited, rows, depth + 1, f)? {
                return Ok(false);
            }
            let total = key_len.checked_add(data_len).filter(|t| *t <= MAX_PAYLOAD).ok_or("payload is too large")?;
            let payload = self.payload(bytes, total, visited)?;
            *rows += 1;
            if *rows > 20_000_000 {
                return Err("too many rows".into());
            }
            if let Some(row) = self.row_of(&payload, key_len) {
                if !f(row) {
                    return Ok(false);
                }
            }
            cell = next;
        }
        self.walk(right, visited, rows, depth + 1, f)
    }

    /// The key and data of a cell, with overflow pages joined.
    fn payload(&self, cell: &[u8], total: usize, visited: &mut HashSet<u32>) -> Result<Vec<u8>, String> {
        let local = total.min(LOCAL);
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(cell.get(12..12 + local).ok_or("cell is cut short")?);
        if total > LOCAL {
            let mut next = self.u32_at(cell, 12 + LOCAL).ok_or("cell is cut short")?;
            while out.len() < total {
                if next == 0 || !visited.insert(next) {
                    return Err("overflow chain ends early or loops".into());
                }
                let page = self.page(next).ok_or_else(|| format!("overflow page {next} is outside the file"))?;
                let take = (total - out.len()).min(PAGE - 4);
                out.extend_from_slice(&page[4..4 + take]);
                next = self.u32_at(page, 0).ok_or("short page")?;
            }
        }
        Ok(out)
    }
}

impl Db<'_> {
    /// A row from a cell's payload; `None` for a key that is not a 4-byte row id (an index entry)
    /// or data that is not a record.
    fn row_of(&self, payload: &[u8], key_len: usize) -> Option<Row> {
        let key = payload.get(..key_len)?;
        let [a, b, c, d] = key else { return None };
        let id = i64::from(i32::from_be_bytes([*a, *b, *c, *d]) ^ i32::MIN);
        Some(Row { id, fields: self.record(payload.get(key_len..)?)? })
    }

    /// The fields of a record. Its offset table has 1, 2 or 3 bytes per entry, the narrowest that
    /// holds the record's length; the width is found by trying each (a table is right when its
    /// first entry is its own size and the last is the record's length).
    fn record(&self, data: &[u8]) -> Option<Vec<Option<String>>> {
        'width: for width in 1..=3usize {
            let at = |i: usize| -> Option<usize> {
                let b = data.get(i * width..i * width + width)?;
                Some(match (width, self.big) {
                    (1, _) => usize::from(b[0]),
                    (2, false) => usize::from(u16::from_le_bytes([b[0], b[1]])),
                    (2, true) => usize::from(u16::from_be_bytes([b[0], b[1]])),
                    (_, false) => usize::from(b[0]) | usize::from(b[1]) << 8 | usize::from(b[2]) << 16,
                    (_, true) => usize::from(b[2]) | usize::from(b[1]) << 8 | usize::from(b[0]) << 16,
                })
            };
            let first = at(0)?;
            if first < width || first % width != 0 || first > data.len() {
                continue;
            }
            let count = first / width - 1;
            if count > 256 || at(count) != Some(data.len()) {
                continue;
            }
            let mut fields = Vec::with_capacity(count);
            let mut previous = first;
            for i in 0..count {
                let (Some(start), Some(end)) = (at(i), at(i + 1)) else { continue 'width };
                if start < previous || end < start {
                    continue 'width;
                }
                previous = end;
                let text = data.get(start..end)?;
                let text = text.strip_suffix(&[0]).unwrap_or(text);
                fields.push((start != end).then(|| String::from_utf8_lossy(text).into_owned()));
            }
            return Some(fields);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixture;

    /// Every table, row for row, as the repository's own `sqlite` shell printed it (`|` between fields, NULL
    /// empty, the INTEGER PRIMARY KEY column showing the row id). Repository made by `svccfg import` of two manifests.
    #[test]
    fn every_table_equals_the_native_shell() {
        let data = fixture("smf-repository/repository.db");
        let db = Db::open(&data).unwrap();
        let pk = ["service_tbl", "instance_tbl", "pg_tbl", "prop_lnk_tbl", "snapshot_lnk_tbl"];
        let mut rows = 0;
        let tables = db.tables().unwrap();
        for (name, root, sql) in &tables {
            if ["id_tbl", "schema_version"].contains(&name.as_str()) {
                continue;
            }
            let reference = String::from_utf8(fixture(&format!("smf-repository/dump.{name}.txt"))).unwrap();
            assert!(sql.starts_with("CREATE TABLE"), "{sql}");
            let mut got = String::new();
            db.scan(*root, |row| {
                let mut fields: Vec<String> = row.fields.iter().map(|f| f.clone().unwrap_or_default()).collect();
                if pk.contains(&name.as_str()) {
                    fields[0] = row.id.to_string();
                }
                got.push_str(&fields.join("|"));
                got.push('\n');
                rows += 1;
                true
            })
            .unwrap();
            assert_eq!(got, reference, "table {name}");
        }
        // 8 of the 10 tables have a reference dump; `id_tbl` and `schema_version` are tiny.
        assert!(rows == 190 && tables.len() == 10, "{rows} rows, {} tables", tables.len());
        assert!(tables.iter().any(|(n, _, _)| n == "value_tbl"));
        assert_eq!(db.root_of("service_tbl").unwrap(), Some(3));
    }

    #[test]
    fn other_files_are_refused() {
        assert!(Db::open(b"SQLite format 3\0").is_err());
        assert!(Db::open(b"").is_err());
        let mut data = fixture("smf-repository/repository.db");
        data[48] ^= 1;
        assert!(Db::open(&data).is_err());
        assert!(is_sqlite2(&fixture("smf-repository/repository.db")));
    }

    /// A page that points at itself, a child outside the file, and a cell chain that never ends.
    #[test]
    fn cycles_and_wild_pointers_end_with_an_error() {
        let data = fixture("smf-repository/repository.db");
        let db_of = |d: &[u8]| Db::open(d).map(|db| db.scan(3, |_| true));
        // The right child of page 3 is page 3.
        let mut cyc = data.clone();
        let at = 2 * PAGE;
        cyc[at..at + 4].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(db_of(&cyc), Ok(Err(_))));
        // A child beyond the end of the file.
        let mut far = data.clone();
        far[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(db_of(&far), Ok(Err(_))));
        // The first cell's `iNext` points at itself.
        let mut looped = data.clone();
        let first = usize::from(u16::from_le_bytes([data[at + 4], data[at + 5]]));
        looped[at + first + 6..at + first + 8].copy_from_slice(&(first as u16).to_le_bytes());
        assert!(matches!(db_of(&looped), Ok(Err(_))));
    }

    /// A two-table database built here in either byte order (SPARC writes it big-endian): the same rows come out.
    fn build(big: bool) -> Vec<u8> {
        let u16b = |v: u16| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let u32b = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let record = |fields: &[Option<&str>]| {
            let mut body = Vec::new();
            let mut offsets = vec![fields.len() as u8 + 1];
            for f in fields {
                if let Some(text) = f {
                    body.extend_from_slice(text.as_bytes());
                    body.push(0);
                }
                offsets.push(offsets[0] + body.len() as u8);
            }
            [offsets, body].concat()
        };
        let page = |rows: &[(i32, Vec<u8>)]| {
            let mut page = vec![0u8; PAGE];
            page[4..6].copy_from_slice(&u16b(8));
            let mut at = 8;
            for (n, (id, data)) in rows.iter().enumerate() {
                let next = if n + 1 == rows.len() { 0 } else { at + 12 + 4 + data.len().div_ceil(4) * 4 };
                page[at + 4..at + 6].copy_from_slice(&u16b(4));
                page[at + 6..at + 8].copy_from_slice(&u16b(next as u16));
                page[at + 10..at + 12].copy_from_slice(&u16b(data.len() as u16));
                page[at + 12..at + 16].copy_from_slice(&(*id as u32 ^ 0x8000_0000).to_be_bytes());
                page[at + 16..at + 16 + data.len()].copy_from_slice(data);
                at = next;
            }
            page
        };
        let mut file = vec![0u8; PAGE];
        file[..MAGIC.len()].copy_from_slice(MAGIC);
        file[48..52].copy_from_slice(&u32b(0xdae3_7528));
        let master = record(&[
            Some("table"),
            Some("service_tbl"),
            Some("service_tbl"),
            Some("3"),
            Some("CREATE TABLE service_tbl (svc_id INTEGER PRIMARY KEY, svc_name CHAR(256))"),
        ]);
        file.extend(page(&[(1, master)]));
        file.extend(page(&[
            (2, record(&[None, Some("milestone/multi-user")])),
            (7, record(&[None, Some("system/cron")])),
            (9, record(&[None, None])),
        ]));
        file
    }

    #[test]
    fn both_byte_orders_give_the_same_rows() {
        let rows = |data: &[u8]| {
            let db = Db::open(data).unwrap();
            let mut out = Vec::new();
            db.scan(db.root_of("service_tbl").unwrap().unwrap(), |r| {
                out.push((r.id, r.fields));
                true
            })
            .unwrap();
            out
        };
        let little = rows(&build(false));
        assert_eq!(little.len(), 3);
        assert_eq!(little[0], (2, vec![None, Some("milestone/multi-user".to_string())]));
        assert_eq!(little[2], (9, vec![None, None]));
        assert_eq!(little, rows(&build(true)));
    }

    #[test]
    fn mutated_files_never_panic() {
        let data = fixture("smf-repository/repository.db");
        let step = data.len() / 1200;
        let walk = |d: &[u8]| {
            if let Ok(db) = Db::open(d) {
                if let Ok(tables) = db.tables() {
                    for (_, root, _) in tables {
                        let _ = db.scan(root, |_| true);
                    }
                }
            }
        };
        for len in (0..data.len()).step_by(step) {
            walk(&data[..len]);
        }
        let mut changed = data.clone();
        for i in (0..data.len()).step_by(step.max(7)) {
            let old = changed[i];
            for byte in [old ^ 0xff, 0, 0xff] {
                changed[i] = byte;
                walk(&changed);
            }
            changed[i] = old;
        }
    }
}

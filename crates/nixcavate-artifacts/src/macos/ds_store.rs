//! Finder `.DS_Store` files: a "buddy allocator" file holding a B-tree of records, one per
//! (file name, attribute). A directory's `.DS_Store` names the files and folders Finder saw in
//! it, including ones deleted since, and records the trash "put back" location of items moved to
//! the Trash (`ptbL` folder, `ptbN` name).
//!
//! Format: the community description of the file ("DSStoreFormat", Mark Mentovai and Wim Lewis)
//! as implemented by the open-source `ds_store` Python project (read for layout only). All
//! integers are big-endian; block addresses are relative to byte 4 of the file; a block address
//! packs the offset (high bits) and `log2(size)` (low 5 bits). View settings (`bwsp`, `lsvp`,
//! `icvp`...) are blobs that are only counted, never decoded.
//!
//! Checked against the public `Test_DS_Store` sample of that project (MIT licence), compared with
//! that project's own reader; other layouts are synthetic only.

use super::util::clip;
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::collections::HashSet;

pub const ARTIFACT: Artifact = Artifact::new(
    "ds-store",
    "Finder .DS_Store: names of files and folders that existed in a directory",
    Category::Filesystem,
    MACOS,
    &["Users/**/.DS_Store", "Applications/**/.DS_Store", "Volumes/**/.DS_Store", "Library/**/.DS_Store"],
    parse,
);

const MAX_BLOCKS: usize = 1 << 20;
const MAX_NODES: usize = 100_000;
const MAX_RECORDS: usize = 2_000_000;
const MAX_LEVELS: u32 = 64;
const MAX_NAME_CHARS: usize = 1024;
const MAX_VALUE_BYTES: usize = 64 << 10;
/// Seconds from 1904-01-01 (the Mac HFS epoch `dutc` counts from) to 1970-01-01.
const HFS_TO_UNIX: i64 = 2_082_844_800;

#[derive(Serialize)]
struct Item<'a> {
    user: &'a str,
    /// The directory that holds this `.DS_Store`.
    directory: &'a str,
    /// The file or folder the record is about (`.` is the directory itself).
    name: String,
    /// The four-letter structure id (`Iloc`, `ptbL`, `modD`...).
    id: String,
    value_type: String,
    value: Option<String>,
    /// For date records (`modD`, `moDD`).
    time: Option<Timestamp>,
}

impl Record for Item<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("Finder recorded {} in {} as modified", self.name, self.directory);
        self.time.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A cursor over one block.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn utf16(&mut self, chars: usize) -> Option<String> {
        let bytes = self.take(chars.checked_mul(2)?)?;
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

struct Store<'a> {
    data: &'a [u8],
    /// Block id to address.
    blocks: Vec<u32>,
}

impl<'a> Store<'a> {
    fn open(data: &'a [u8]) -> Result<(Store<'a>, u32)> {
        if be32(data, 0) != Some(1) || data.get(4..8) != Some(b"Bud1") {
            return Err(Error::format("not a .DS_Store file (no Bud1 header)"));
        }
        let (offset, size, again) = (be32(data, 8), be32(data, 12), be32(data, 16));
        let (Some(offset), Some(size), Some(again)) = (offset, size, again) else {
            return Err(Error::format("truncated .DS_Store header"));
        };
        if offset != again {
            return Err(Error::format("root block addresses differ"));
        }
        let root = Self::slice(data, offset as usize, size as usize)
            .ok_or_else(|| Error::format("root block lies outside the file"))?;
        let mut cursor = Cursor { data: root, pos: 0 };
        let (count, _) = (cursor.u32(), cursor.u32());
        let count = count.ok_or_else(|| Error::format("truncated root block"))? as usize;
        if count > MAX_BLOCKS || count.saturating_mul(4) > root.len() {
            return Err(Error::format(format!("{count} blocks does not fit the root block")));
        }
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            blocks.push(cursor.u32().ok_or_else(|| Error::format("truncated block table"))?);
        }
        // The table is padded to a multiple of 256 entries.
        cursor.pos = 8 + count.div_ceil(256) * 256 * 4;
        let toc = cursor.u32().ok_or_else(|| Error::format("truncated table of contents"))?;
        let mut superblock = None;
        for _ in 0..toc.min(4096) {
            let len = cursor.take(1).map(|b| b[0] as usize);
            let name = len.and_then(|l| cursor.take(l));
            let value = cursor.u32();
            match (name, value) {
                (Some(name), Some(value)) => {
                    if name == b"DSDB" {
                        superblock = Some(value);
                    }
                }
                _ => break,
            }
        }
        let store = Store { data, blocks };
        let superblock = superblock.ok_or_else(|| Error::format("no DSDB entry in the table of contents"))?;
        Ok((store, superblock))
    }

    fn slice(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
        let start = offset.checked_add(4)?;
        data.get(start..start.checked_add(size)?)
    }

    fn block(&self, id: u32) -> Option<&'a [u8]> {
        let address = *self.blocks.get(usize::try_from(id).ok()?)?;
        let (offset, bits) = ((address & !0x1f) as usize, address & 0x1f);
        if bits >= 31 {
            return None;
        }
        Self::slice(self.data, offset, 1usize << bits)
    }
}

struct Walk<'a, 'b> {
    store: &'b Store<'a>,
    seen: HashSet<u32>,
    records: usize,
    stopped: bool,
}

/// One record as read from a node.
struct Entry {
    name: String,
    id: String,
    value_type: String,
    value: Option<String>,
    time: Option<Timestamp>,
}

fn entry(cursor: &mut Cursor) -> std::result::Result<Entry, String> {
    let chars = cursor.u32().ok_or("truncated record")? as usize;
    if chars > MAX_NAME_CHARS {
        return Err(format!("file name of {chars} characters"));
    }
    let name = cursor.utf16(chars).ok_or("truncated file name")?;
    let id = String::from_utf8_lossy(cursor.take(4).ok_or("truncated record")?).into_owned();
    let kind = cursor.take(4).ok_or("truncated record")?;
    let value_type = String::from_utf8_lossy(kind).into_owned();
    let mut time = None;
    let value = match kind {
        b"bool" => Some(((cursor.take(1).ok_or("truncated value")?[0]) != 0).to_string()),
        b"long" | b"shor" => Some(cursor.u32().ok_or("truncated value")?.to_string()),
        b"comp" => Some(
            u64::from_be_bytes(cursor.take(8).ok_or("truncated value")?.try_into().map_err(|_| "value")?).to_string(),
        ),
        b"dutc" => {
            let raw = u64::from_be_bytes(cursor.take(8).ok_or("truncated value")?.try_into().map_err(|_| "value")?);
            let secs = i64::try_from(raw >> 16).ok().and_then(|s| s.checked_sub(HFS_TO_UNIX));
            let nanos = (u64::from(raw as u16) * 1_000_000_000 / 65536) as u32;
            time = secs.and_then(|s| Timestamp::checked(s, nanos / 1000 * 1000, Precision::Micros, Basis::Recorded));
            Some(raw.to_string())
        }
        b"type" => Some(String::from_utf8_lossy(cursor.take(4).ok_or("truncated value")?).into_owned()),
        b"ustr" => {
            let chars = cursor.u32().ok_or("truncated value")? as usize;
            if chars > MAX_VALUE_BYTES / 2 {
                return Err(format!("string of {chars} characters"));
            }
            Some(clip(&cursor.utf16(chars).ok_or("truncated value")?, 512))
        }
        b"blob" => {
            let len = cursor.u32().ok_or("truncated value")? as usize;
            if len > MAX_VALUE_BYTES {
                return Err(format!("blob of {len} bytes"));
            }
            cursor.take(len).ok_or("truncated value")?;
            Some(format!("<blob {len} bytes>"))
        }
        other => return Err(format!("unknown value type {:?}", String::from_utf8_lossy(other))),
    };
    Ok(Entry { name, id, value_type, value, time })
}

impl Walk<'_, '_> {
    fn node(&mut self, id: u32, depth: u32, emit: &mut dyn FnMut(Entry) -> Result<()>, sink: &mut Sink) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if depth > MAX_LEVELS || self.seen.len() >= MAX_NODES || !self.seen.insert(id) {
            sink.warn(format!("B-tree node {id}: repeated, too deep or too many nodes; not followed"));
            return Ok(());
        }
        let Some(block) = self.store.block(id) else {
            sink.warn(format!("B-tree node {id}: block lies outside the file"));
            return Ok(());
        };
        let mut cursor = Cursor { data: block, pos: 0 };
        let (Some(next), Some(count)) = (cursor.u32(), cursor.u32()) else {
            sink.warn(format!("B-tree node {id}: truncated"));
            return Ok(());
        };
        // Every record is at least 16 bytes, so a count beyond that is damaged.
        let count = (count as usize).min(block.len() / 12 + 1);
        for _ in 0..count {
            if next != 0 {
                let Some(child) = cursor.u32() else { break };
                self.node(child, depth + 1, emit, sink)?;
            }
            match entry(&mut cursor) {
                Ok(e) => {
                    self.records += 1;
                    if self.records > MAX_RECORDS {
                        sink.warn(format!("more than {MAX_RECORDS} records; stopped"));
                        self.stopped = true;
                        return Ok(());
                    }
                    emit(e)?;
                }
                Err(why) => {
                    sink.warn(format!("B-tree node {id}: {why}; rest of the node skipped"));
                    return Ok(());
                }
            }
        }
        if next != 0 {
            self.node(next, depth + 1, emit, sink)?;
        }
        Ok(())
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let (store, superblock) = Store::open(input.data)?;
    let block = store.block(superblock).ok_or_else(|| Error::format("DSDB block lies outside the file"))?;
    let mut cursor = Cursor { data: block, pos: 0 };
    let (root, levels, _records, _nodes, _page) =
        (cursor.u32(), cursor.u32(), cursor.u32(), cursor.u32(), cursor.u32());
    let (Some(root), Some(levels)) = (root, levels) else { return Err(Error::format("truncated DSDB block")) };
    if levels > MAX_LEVELS {
        return Err(Error::format(format!("B-tree of {levels} levels is not plausible")));
    }
    let user = user_from_path(input.path);
    let directory = input.path.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut walk = Walk { store: &store, seen: HashSet::new(), records: 0, stopped: false };
    let mut pending: Vec<Entry> = Vec::new();
    walk.node(
        root,
        0,
        &mut |e| {
            pending.push(e);
            Ok(())
        },
        sink,
    )?;
    for e in pending {
        sink.emit(
            Loc::None,
            &Item { user, directory, name: e.name, id: e.id, value_type: e.value_type, value: e.value, time: e.time },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Users/alice/Documents/.DS_Store";

    #[test]
    fn reads_names_putback_info_and_dates() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("ds-store/Synthetic_DS_Store"), 0));
    }

    #[test]
    fn a_tree_with_internal_nodes() {
        let out = run(&ARTIFACT, PATH, &fixture("ds-store/Tree_DS_Store"), 0);
        for name in ["aaa", "bbb", "ccc", "ddd"] {
            assert!(out.contains(&format!("\"name\":\"{name}\"")), "{name} in {out}");
        }
    }

    #[test]
    fn not_a_ds_store() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("failed: "));
        assert!(run(&ARTIFACT, PATH, b"\0\0\0\x01Bud2", 0).contains("failed: "));
    }

    #[test]
    fn damaged_files_do_not_panic() {
        for name in ["Synthetic_DS_Store", "Tree_DS_Store"] {
            let data = fixture(&format!("ds-store/{name}"));
            crate::macos::util::survives_sparse(&ARTIFACT, PATH, &data, 61, 400);
        }
    }

    #[test]
    fn a_node_that_points_at_itself_ends() {
        let mut data = fixture("ds-store/Tree_DS_Store");
        // Every aligned word set to 1 in turn: cycles, wild block ids and counts.
        for at in (0..data.len().saturating_sub(4)).step_by(4) {
            let saved: [u8; 4] = data[at..at + 4].try_into().unwrap();
            data[at..at + 4].copy_from_slice(&1u32.to_be_bytes());
            run(&ARTIFACT, PATH, &data, 0);
            data[at..at + 4].copy_from_slice(&saved);
        }
    }

    /// The public Test_DS_Store sample: `NIXCAVATE_DS_STORE=<file> cargo test ... public_sample -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs the public sample; see docs/LIMITATIONS.md"]
    fn public_sample() {
        let data = std::fs::read(std::env::var("NIXCAVATE_DS_STORE").unwrap()).unwrap();
        println!("{}", run(&ARTIFACT, PATH, &data, 0));
    }
}

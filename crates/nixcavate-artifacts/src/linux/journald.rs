//! systemd journal files. Format: the systemd "Journal File Format" documentation
//! (systemd.io/JOURNAL_FILE_FORMAT): regular and compact (systemd >= 252) layouts, with DATA
//! payloads compressed by XZ, LZ4 or ZSTD.
//!
//! Objects are scanned in file order from the end of the header rather than through the entry
//! array chain: the scan needs only each object's own size, so it survives broken arrays and
//! emits entries in the order they were appended.

use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::Read;

pub const ARTIFACT: Artifact = Artifact::new(
    "journald",
    "systemd journal entries",
    Category::Logs,
    LINUX,
    &["var/log/journal/**/*.journal", "var/log/journal/**/*.journal~", "run/log/journal/**/*.journal"],
    parse,
);

const SIGNATURE: &[u8] = b"LPKSHHRH";
/// The header as of systemd 187; every later field is optional to us.
const MIN_HEADER: u64 = 208;
const INCOMPATIBLE_COMPACT: u32 = 16;
const KNOWN_INCOMPATIBLE: u32 = 0x1f;
const OBJECT_DATA: u8 = 1;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_TAG: u8 = 7;
const COMPRESSED_XZ: u8 = 1;
const COMPRESSED_LZ4: u8 = 2;
const COMPRESSED_ZSTD: u8 = 4;
const ENTRY_HEADER: usize = 64;
/// Decompressed bytes allowed per entry. No real entry comes near this; it stops a small file
/// of highly compressed objects from exhausting memory.
const MAX_PAYLOAD: usize = 256 << 20;
/// Decompressed payloads kept for reuse; dropped and rebuilt past this.
const MAX_CACHED: usize = 64 << 20;
const MESSAGE_CHARS: usize = 300;
/// journald refuses longer field names, so the `=` is never further in than this.
const MAX_FIELD_NAME: usize = 64;

#[derive(Serialize)]
struct Entry<'a> {
    time: Timestamp,
    monotonic_usec: u64,
    boot_id: BootId,
    seqnum: u64,
    log_host: Option<Cow<'a, str>>,
    unit: Option<Cow<'a, str>>,
    program: Option<Cow<'a, str>>,
    pid: Option<u32>,
    uid: Option<u32>,
    priority: Option<u8>,
    message: Option<Cow<'a, str>>,
    command: Option<Cow<'a, str>>,
    transport: Option<Cow<'a, str>>,
    fields: Fields<'a>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = truncate(self.message.as_deref().unwrap_or(""), MESSAGE_CHARS);
        let text = match &self.program {
            Some(program) => format!("{program}: {message}"),
            None => message.to_string(),
        };
        let text = truncate(&text, MESSAGE_CHARS).to_string();
        std::iter::once(Event::new(self.time, "log", text))
    }
}

fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

struct BootId([u8; 16]);

impl Serialize for BootId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 32];
        for (i, b) in self.0.iter().enumerate() {
            buf[2 * i] = HEX[usize::from(b >> 4)];
            buf[2 * i + 1] = HEX[usize::from(b & 15)];
        }
        s.serialize_str(std::str::from_utf8(&buf).unwrap_or_default())
    }
}

/// Where a DATA object's `FIELD=value` bytes are: in the file or in the decompression arena.
#[derive(Clone, Copy)]
struct Payload {
    in_arena: bool,
    start: usize,
    len: usize,
    /// Position of the `=`.
    eq: usize,
}

#[derive(Clone, Copy)]
struct Bytes<'a> {
    data: &'a [u8],
    arena: &'a [u8],
}

impl<'a> Bytes<'a> {
    fn get(self, p: &Payload) -> &'a [u8] {
        let buf = if p.in_arena { self.arena } else { self.data };
        buf.get(p.start..p.start + p.len).unwrap_or_default()
    }

    fn key(self, p: &Payload) -> &'a [u8] {
        self.get(p).get(..p.eq).unwrap_or_default()
    }

    fn value(self, p: &Payload) -> &'a [u8] {
        self.get(p).get(p.eq + 1..).unwrap_or_default()
    }
}

/// Every field without a column of its own, sorted by name. A field that occurs more than
/// once in an entry becomes an array, as `journalctl -o json` shows it.
struct Fields<'a> {
    items: &'a [Payload],
    bytes: Bytes<'a>,
}

impl Serialize for Fields<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        let mut rest = self.items;
        while let Some(first) = rest.first() {
            let key = self.bytes.key(first);
            let n = rest.iter().take_while(|p| self.bytes.key(p) == key).count();
            let (group, tail) = rest.split_at(n);
            if n == 1 {
                map.serialize_entry(&lossy(key), &lossy(self.bytes.value(first)))?;
            } else {
                map.serialize_entry(&lossy(key), &Values { items: group, bytes: self.bytes })?;
            }
            rest = tail;
        }
        map.end()
    }
}

struct Values<'a> {
    items: &'a [Payload],
    bytes: Bytes<'a>,
}

impl Serialize for Values<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.items.len()))?;
        for p in self.items {
            seq.serialize_element(&lossy(self.bytes.value(p)))?;
        }
        seq.end()
    }
}

/// DATA offsets are 8-aligned file positions; multiplying spreads them well enough.
#[derive(Default)]
struct OffsetHasher(u64);

impl Hasher for OffsetHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (n >> 3).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

struct Reader<'a> {
    data: &'a [u8],
    header_size: usize,
    compact: bool,
    /// Compressed DATA objects are shared by many entries: each is decompressed once.
    cache: HashMap<u64, std::result::Result<Payload, &'static str>, BuildHasherDefault<OffsetHasher>>,
    arena: Vec<u8>,
    zstd: Option<zstd::bulk::Decompressor<'static>>,
    zstd_buf: Vec<u8>,
    /// What the current entry may still decompress.
    budget: usize,
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

impl Reader<'_> {
    /// The `FIELD=value` payload of the DATA object at `offset`.
    fn data_object(&mut self, offset: u64) -> std::result::Result<Payload, &'static str> {
        let at = usize::try_from(offset).ok().filter(|&at| at % 8 == 0 && at >= self.header_size);
        let at = at.ok_or("item offset is out of range")?;
        let head = self.data.get(at..at.saturating_add(16)).ok_or("item offset is out of range")?;
        if head[0] != OBJECT_DATA {
            return Err("item does not point at a DATA object");
        }
        let size = usize::try_from(u64_at(head, 8).unwrap_or(0)).unwrap_or(usize::MAX);
        let object = self.data.get(at..at.saturating_add(size)).ok_or("DATA object runs past the end of the file")?;
        let header = if self.compact { 72 } else { 64 };
        let payload = object.get(header..).ok_or("DATA object is too short")?;
        let flags = head[1] & (COMPRESSED_XZ | COMPRESSED_LZ4 | COMPRESSED_ZSTD);
        if flags == 0 {
            let eq = field_end(payload)?;
            return Ok(Payload { in_arena: false, start: at + header, len: payload.len(), eq });
        }
        if let Some(cached) = self.cache.get(&offset) {
            return *cached;
        }
        let full_budget = self.budget == MAX_PAYLOAD;
        let result = self.decompress(flags, payload);
        // A failure for lack of budget says nothing about the object itself.
        if result.is_ok() || full_budget {
            self.cache.insert(offset, result);
        }
        result
    }

    fn decompress(&mut self, flags: u8, payload: &[u8]) -> std::result::Result<Payload, &'static str> {
        let start = self.arena.len();
        let limit = self.budget;
        let ok = match flags {
            COMPRESSED_XZ => {
                xz2::read::XzDecoder::new(payload).take(limit as u64 + 1).read_to_end(&mut self.arena).is_ok()
            }
            COMPRESSED_LZ4 => {
                // An 8-byte little-endian decompressed size, then one raw LZ4 block.
                let size = u64_at(payload, 0).and_then(|n| usize::try_from(n).ok()).unwrap_or(usize::MAX);
                let block = payload.get(8..).unwrap_or_default();
                // LZ4 cannot expand a block by more than 255 times.
                if size > limit || size > block.len().saturating_mul(255) {
                    return Err("LZ4 payload claims an impossible or oversized size");
                }
                self.arena.resize(start + size, 0);
                matches!(lz4_flex::block::decompress_into(block, &mut self.arena[start..]), Ok(n) if n == size)
            }
            COMPRESSED_ZSTD => match zstd::zstd_safe::get_frame_content_size(payload) {
                Ok(Some(size)) if size <= limit as u64 => {
                    let zstd = self.zstd.get_or_insert_with(Default::default);
                    self.zstd_buf.clear();
                    self.zstd_buf.reserve(size as usize);
                    let ok =
                        matches!(zstd.decompress_to_buffer(payload, &mut self.zstd_buf), Ok(n) if n as u64 == size);
                    self.arena.extend_from_slice(&self.zstd_buf);
                    ok
                }
                Ok(Some(_)) => return Err("ZSTD payload claims an oversized size"),
                // Frames that do not record their size are streamed.
                _ => zstd::stream::read::Decoder::new(payload)
                    .is_ok_and(|decoder| decoder.take(limit as u64 + 1).read_to_end(&mut self.arena).is_ok()),
            },
            _ => return Err("DATA object has more than one compression flag"),
        };
        let len = self.arena.len() - start;
        if !ok || len > limit {
            self.arena.truncate(start);
            return Err("compressed DATA payload does not decompress");
        }
        self.budget -= len;
        let eq = field_end(&self.arena[start..])?;
        Ok(Payload { in_arena: true, start, len, eq })
    }

    /// Emits the ENTRY object `object`, which starts at file offset `at`.
    fn entry(&mut self, at: usize, object: &[u8], items: &mut Vec<Payload>, sink: &mut Sink) -> Result<()> {
        let (Some(seqnum), Some(realtime), Some(monotonic), Some(boot)) =
            (u64_at(object, 16), u64_at(object, 24), u64_at(object, 32), object.get(40..56))
        else {
            sink.warn(format!("offset {at}: ENTRY object is too short"));
            return Ok(());
        };
        let mut boot_id = [0u8; 16];
        boot_id.copy_from_slice(boot);
        if self.arena.len() > MAX_CACHED {
            self.arena.clear();
            self.cache.clear();
        }
        self.budget = MAX_PAYLOAD;
        items.clear();
        let width = if self.compact { 4 } else { 16 };
        for item in object.get(ENTRY_HEADER..).unwrap_or_default().chunks_exact(width) {
            let offset = if self.compact { u32_at(item, 0).map(u64::from) } else { u64_at(item, 0) };
            match self.data_object(offset.unwrap_or(0)) {
                Ok(payload) => items.push(payload),
                Err(why) => sink.warn(format!("offset {at}: entry field at {}: {why}", offset.unwrap_or(0))),
            }
        }

        let bytes = Bytes { data: self.data, arena: &self.arena };
        let mut entry = Entry {
            time: Timestamp::from_micros(i64::try_from(realtime).unwrap_or(i64::MAX), Basis::Recorded),
            monotonic_usec: monotonic,
            boot_id: BootId(boot_id),
            seqnum,
            log_host: None,
            unit: None,
            program: None,
            pid: None,
            uid: None,
            priority: None,
            message: None,
            command: None,
            transport: None,
            fields: Fields { items: &[], bytes },
        };
        // Fallback sources for `unit` and `program` also stay in `fields`.
        let (mut unit, mut user_unit, mut comm) = (None, None, None);
        items.retain(|p| {
            let value = bytes.value(p);
            let number = |v: &[u8]| parse_uint(v).and_then(|n| u32::try_from(n).ok());
            match bytes.key(p) {
                b"MESSAGE" => !fill(&mut entry.message, value),
                b"_HOSTNAME" => !fill(&mut entry.log_host, value),
                b"_SYSTEMD_UNIT" => !fill(&mut entry.unit, value),
                b"SYSLOG_IDENTIFIER" => !fill(&mut entry.program, value),
                b"_CMDLINE" => !fill(&mut entry.command, value),
                b"_TRANSPORT" => !fill(&mut entry.transport, value),
                b"_PID" if entry.pid.is_none() && number(value).is_some() => {
                    entry.pid = number(value);
                    false
                }
                b"_UID" if entry.uid.is_none() && number(value).is_some() => {
                    entry.uid = number(value);
                    false
                }
                b"PRIORITY" if entry.priority.is_none() && number(value).is_some_and(|n| n <= 255) => {
                    entry.priority = number(value).map(|n| n as u8);
                    false
                }
                key => {
                    match key {
                        b"UNIT" => unit = unit.or(Some(value)),
                        b"_SYSTEMD_USER_UNIT" => user_unit = user_unit.or(Some(value)),
                        b"_COMM" => comm = comm.or(Some(value)),
                        _ => {}
                    }
                    true
                }
            }
        });
        entry.unit = entry.unit.or(unit.or(user_unit).map(lossy));
        entry.program = entry.program.or(comm.map(lossy));
        // Stable, so repeated fields keep their order within the entry.
        items.sort_by(|a, b| bytes.key(a).cmp(bytes.key(b)));
        entry.fields.items = items;
        sink.emit(Loc::Offset(at as u64), &entry)
    }
}

/// The position of the `=` that ends the field name.
fn field_end(payload: &[u8]) -> std::result::Result<usize, &'static str> {
    memchr::memchr(b'=', &payload[..payload.len().min(MAX_FIELD_NAME + 1)]).ok_or("DATA payload has no field name")
}

/// Fills an empty column; false when it already held a value.
fn fill<'a>(slot: &mut Option<Cow<'a, str>>, value: &'a [u8]) -> bool {
    let empty = slot.is_none();
    if empty {
        *slot = Some(lossy(value));
    }
    empty
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if !data.starts_with(SIGNATURE) {
        return Err(Error::format("not a journal file (bad signature)"));
    }
    let header = |at| u64_at(data, at).ok_or_else(|| Error::format("journal header is truncated"));
    let incompatible = u32_at(data, 12).ok_or_else(|| Error::format("journal header is truncated"))?;
    let (header_size, arena_size, tail_object) = (header(88)?, header(96)?, header(136)?);
    if header_size < MIN_HEADER || header_size % 8 != 0 || header_size > data.len() as u64 {
        return Err(Error::format(format!("implausible journal header size {header_size}")));
    }
    if incompatible & !KNOWN_INCOMPATIBLE != 0 {
        sink.warn(format!("unknown incompatible flags {incompatible:#x}; reading anyway"));
    }
    let arena_end = header_size.saturating_add(arena_size);
    if arena_end > data.len() as u64 {
        sink.warn(format!("file is truncated: the arena ends at {arena_end}, the file at {}", data.len()));
    }
    let end = arena_end.min(data.len() as u64) as usize;
    let mut reader = Reader {
        data,
        header_size: header_size as usize,
        compact: incompatible & INCOMPATIBLE_COMPACT != 0,
        cache: HashMap::default(),
        arena: Vec::new(),
        zstd: None,
        zstd_buf: Vec::new(),
        budget: MAX_PAYLOAD,
    };
    let mut items = Vec::new();
    let mut at = header_size as usize;
    // Each object is at least 16 bytes, so the scan always moves forward.
    while let Some(head) = data.get(at..at + 16).filter(|_| at + 16 <= end) {
        let (kind, size) = (head[0], u64_at(head, 8).unwrap_or(0));
        if kind == 0 && size == 0 {
            // Preallocated space after the last object.
            if (at as u64) < tail_object {
                sink.warn(format!("offset {at}: unwritten space before the last object; stopping"));
            }
            break;
        }
        if !(OBJECT_DATA..=OBJECT_TAG).contains(&kind) || size < 16 || size > (end - at) as u64 {
            sink.warn(format!("offset {at}: corrupt object header (type {kind}, size {size}); stopping"));
            break;
        }
        let size = size as usize;
        if kind == OBJECT_ENTRY {
            reader.entry(at, &data[at..at + size], &mut items, sink)?;
        }
        at += size.next_multiple_of(8);
    }
    if sink.records() == 0 {
        return Err(Error::skipped("no journal entries"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "var/log/journal/0123456789abcdef0123456789abcdef/system.journal";
    const VARIANTS: [&str; 10] = [
        "compact-none",
        "compact-zstd",
        "compact-lz4",
        "compact-xz",
        "regular-none",
        "regular-zstd",
        "regular-lz4",
        "regular-xz",
        "v249-zstd",
        "v245-lz4",
    ];

    /// Fixtures are stored zstd-compressed: a journal file is mostly preallocated zeros.
    fn journal(name: &str) -> Vec<u8> {
        zstd::decode_all(&fixture(&format!("journald/{name}.journal.zst"))[..]).unwrap()
    }

    #[test]
    fn parses_every_variant() {
        for name in VARIANTS {
            insta::assert_snapshot!(name, run(&ARTIFACT, PATH, &journal(name), 0));
        }
    }

    /// Every variant must reproduce what `journalctl -o json --all` printed for it: the same
    /// entries in the same order, with the same timestamps and the same fields.
    #[test]
    fn matches_journalctl() {
        let expected: Vec<serde_json::Value> = String::from_utf8(fixture("journald/journalctl.json"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for name in VARIANTS {
            let out = run(&ARTIFACT, PATH, &journal(name), 0);
            let ours: Vec<serde_json::Value> =
                out.lines().take_while(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect();
            assert_eq!(ours.len(), expected.len(), "{name}");
            for (ours, theirs) in ours.iter().zip(&expected) {
                assert_eq!(fields_of(ours, theirs), journalctl_fields(theirs), "{name}");
                let fallback = |names: &[&str]| names.iter().find_map(|n| theirs.get(*n)).cloned();
                assert_eq!(
                    ours["unit"],
                    fallback(&["_SYSTEMD_UNIT", "UNIT", "_SYSTEMD_USER_UNIT"]).unwrap_or_default()
                );
                assert_eq!(ours["program"], fallback(&["SYSLOG_IDENTIFIER", "_COMM"]).unwrap_or_default());
                // The entry header's boot ID, which journald also stores as a field.
                assert_eq!(ours["boot_id"], theirs["_BOOT_ID"]);
            }
        }
    }

    /// Our record turned back into journal field names and values.
    fn fields_of(record: &serde_json::Value, theirs: &serde_json::Value) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let text = |v: &serde_json::Value| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        for (column, name) in [
            ("log_host", "_HOSTNAME"),
            ("pid", "_PID"),
            ("uid", "_UID"),
            ("priority", "PRIORITY"),
            ("message", "MESSAGE"),
            ("command", "_CMDLINE"),
            ("transport", "_TRANSPORT"),
        ] {
            if !record[column].is_null() {
                out.push((name.to_string(), text(&record[column])));
            }
        }
        // `unit` and `program` hold a field of their own only when journalctl shows it; their
        // fallbacks stay in `fields`.
        for (column, name) in [("unit", "_SYSTEMD_UNIT"), ("program", "SYSLOG_IDENTIFIER")] {
            if theirs.get(name).is_some() {
                out.push((name.to_string(), text(&record[column])));
            }
        }
        let fields = record["fields"].as_object().unwrap();
        for (name, value) in fields {
            match value {
                serde_json::Value::Array(values) => out.extend(values.iter().map(|v| (name.clone(), text(v)))),
                v => out.push((name.clone(), text(v))),
            }
        }
        out.push(("__REALTIME_TIMESTAMP".into(), micros(record["time"].as_str().unwrap())));
        out.push(("__MONOTONIC_TIMESTAMP".into(), record["monotonic_usec"].to_string()));
        out.sort();
        out
    }

    /// journalctl's fields, with binary values (byte arrays) decoded like our lossy text.
    fn journalctl_fields(entry: &serde_json::Value) -> Vec<(String, String)> {
        let text = |v: &serde_json::Value| match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(bytes) => {
                let bytes: Vec<u8> = bytes.iter().map(|b| b.as_u64().unwrap() as u8).collect();
                String::from_utf8_lossy(&bytes).into_owned()
            }
            other => panic!("unexpected value {other}"),
        };
        let mut out = Vec::new();
        for (name, value) in entry.as_object().unwrap() {
            if name == "__CURSOR" || name == "__SEQNUM" || name == "__SEQNUM_ID" {
                continue;
            }
            // A repeated field is an array of values (each a string or a byte array).
            match value {
                serde_json::Value::Array(values) if values.iter().all(|v| !v.is_number()) => {
                    out.extend(values.iter().map(|v| (name.clone(), text(v))))
                }
                v => out.push((name.clone(), text(v))),
            }
        }
        out.sort();
        out
    }

    /// RFC 3339 with microseconds back to epoch microseconds.
    fn micros(rfc3339: &str) -> String {
        let (parsed, _) = nixcavate_core::time::parse_iso8601(rfc3339.as_bytes()).unwrap();
        (parsed.recorded().unwrap().utc / 1000).to_string()
    }

    #[test]
    fn empty_and_foreign_files() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, PATH, b"LPKSHHRH\0\0", 0).contains("failed:"));
        assert!(run(&ARTIFACT, PATH, &[7u8; 4096], 0).contains("failed:"));
        let mut header_only = journal("compact-zstd");
        header_only.truncate(264);
        assert!(run(&ARTIFACT, PATH, &header_only, 0).contains("skipped: no journal entries"));
    }

    /// A compressed DATA object that lies about its size loses that field, not the entry.
    #[test]
    fn lying_lz4_size() {
        let mut data = journal("regular-lz4");
        let mut at = u64_at(&data, 88).unwrap() as usize;
        while !(data[at] == OBJECT_DATA && data[at + 1] == COMPRESSED_LZ4) {
            let size = u64_at(&data, at + 8).unwrap() as usize;
            assert!(size >= 16, "no LZ4-compressed DATA object in the fixture");
            at += size.next_multiple_of(8);
        }
        data[at + 64..at + 72].copy_from_slice(&(1u64 << 40).to_le_bytes());
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 10, "{out}");
        assert!(out.contains("LZ4 payload claims an impossible or oversized size"), "{out}");
    }

    #[test]
    fn truncated_and_corrupt_input_does_not_panic() {
        for name in ["compact-zstd", "regular-lz4", "regular-xz"] {
            let data = journal(name);
            // The written part of the file: everything after it is preallocated zeros.
            let used = data.iter().rposition(|&b| b != 0).unwrap() + 1;
            for len in (0..used).step_by(97).chain([used]) {
                run(&ARTIFACT, PATH, &data[..len], 0);
            }
            let mut seed = 0x2545_f491_4f6c_dd1du64;
            for _ in 0..300 {
                let mut bad = data[..used].to_vec();
                for _ in 0..8 {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    let at = (seed % used as u64) as usize;
                    bad[at] ^= (seed >> 32) as u8 | 1;
                }
                run(&ARTIFACT, PATH, &bad, 0);
            }
        }
    }
}

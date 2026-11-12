//! Biome streams: `.../Biome/streams/<scope>/<stream>/{local,remote/<device>}/<file>`, the
//! macOS 13+ successor of much of KnowledgeC. Each file is a SEGB container of protobuf records.
//!
//! References (public descriptions only): CCL Solutions Group, "Biome" / SEGB format write-ups
//! by Alex Caithness (2022, and the later v2 notes), Ian Whiffin and Heather Mahalik on Biome
//! streams. Times are Mac absolute time (seconds since 2001-01-01 UTC, little-endian f64).
//!
//! v1 (macOS 13 and earlier): 56-byte file header with `SEGB` at offset 52, then records. Each
//! record has a 32-byte header: u32 payload length, u32 state, f64 time 1, f64 time 2, u32
//! CRC, u32 unknown; the payload follows and the next record starts at the next 8-byte
//! boundary. A zeroed header marks unused, pre-allocated space.
//!
//! v2 (macOS 14+): `SEGB` at offset 0, a 32-byte header (u32 entry count at 4, f64 creation
//! time at 8), entry data from offset 32, and a trailer at the very end of the file with one
//! 16-byte entry per record: u32 end offset (relative to offset 32), u32 state, f64 time.
//!
//! The v2 layout was checked against real files (214 stream files, 490,000 records): record
//! times are plausible throughout, and 99.97% of written entries decode as protobuf when an
//! entry starts at the 4-byte boundary after the previous end, with an 8-byte preamble (CRC
//! and unknown) before the payload. The trailer is stored from the end of the file backwards
//! and is not always in offset order, so it is sorted. Deleted entries keep their slot but
//! their payload is wiped.
//!
//! No real v1 file was available. Unconfirmed for v1: the contents of the first 52 bytes of
//! the header; which of the two times is the record time (time 1 is used); the 8-byte record
//! alignment. In both versions the CRC and unknown fields are ignored and the state values
//! are 1 written, 3 deleted, others unknown.
//!
//! Payload schemas depend on the stream and are not public in general, so payloads are decoded
//! generically from the protobuf wire format (see [`decode`]).

use super::plist_util::{mac_time, or_warn};
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::{Map, Value};

pub const ARTIFACT: Artifact = Artifact::new(
    "biome",
    "macOS Biome activity streams",
    Category::Activity,
    MACOS,
    &[
        "Users/*/Library/Biome/streams/*/*/local/*",
        "Users/*/Library/Biome/streams/*/*/remote/*/*",
        "private/var/db/biome/streams/*/*/local/*",
        "private/var/db/biome/streams/*/*/remote/*/*",
        // Deleted records are kept in a `tombstone` store next to the data.
        "Users/*/Library/Biome/streams/*/*/local/tombstone/*",
        "Users/*/Library/Biome/streams/*/*/remote/*/tombstone/*",
        "private/var/db/biome/streams/*/*/local/tombstone/*",
        "private/var/db/biome/streams/*/*/remote/*/tombstone/*",
    ],
    parse,
);

const MAGIC: &[u8; 4] = b"SEGB";
const V1_HEADER: usize = 56;
const V1_RECORD_HEADER: usize = 32;
const V2_HEADER: usize = 32;
const V2_TRAILER_ENTRY: usize = 16;
/// CRC and unknown field before a v2 payload (assumed, see the module comment).
const V2_PREAMBLE: usize = 8;
const MAX_DEPTH: usize = 8;
const SUMMARY_TEXTS: usize = 5;
const SUMMARY_CHARS: usize = 200;

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    stream: &'a str,
    state: &'static str,
    user: &'a str,
    fields: Value,
    summary: String,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "biome", format!("{}: {}", self.stream, self.summary))).into_iter()
    }
}

struct Raw<'a> {
    offset: u64,
    /// Mac absolute time as stored.
    time: Option<f64>,
    state: u32,
    payload: &'a [u8],
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn f64_at(data: &[u8], at: usize) -> Option<f64> {
    Some(f64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn align8(n: usize) -> Option<usize> {
    n.checked_add(7).map(|n| n & !7)
}

fn v1<'a>(data: &'a [u8], warn: &mut Vec<String>) -> Vec<Raw<'a>> {
    let mut out = Vec::new();
    let mut pos = V1_HEADER;
    while let Some(header) = pos.checked_add(V1_RECORD_HEADER).and_then(|end| data.get(pos..end)) {
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let len = u32_at(header, 0).unwrap_or(0) as usize;
        let start = pos + V1_RECORD_HEADER;
        let Some(payload) = start.checked_add(len).and_then(|end| data.get(start..end)) else {
            warn.push(format!("offset {pos}: record length {len} runs past the end of the file"));
            break;
        };
        out.push(Raw { offset: pos as u64, time: f64_at(header, 8), state: u32_at(header, 4).unwrap_or(0), payload });
        match align8(start + len) {
            Some(next) => pos = next,
            None => break,
        }
    }
    out
}

fn v2<'a>(data: &'a [u8], warn: &mut Vec<String>) -> Result<Vec<Raw<'a>>> {
    let count = u32_at(data, 4).unwrap_or(0) as usize;
    let trailer = count
        .checked_mul(V2_TRAILER_ENTRY)
        .and_then(|n| data.len().checked_sub(n))
        .filter(|&t| t >= V2_HEADER)
        .ok_or_else(|| Error::format(format!("SEGB v2 entry table for {count} entries does not fit in the file")))?;
    let mut table = Vec::new();
    for i in 0..count {
        let at = trailer + i * V2_TRAILER_ENTRY;
        let (Some(end), Some(state)) = (u32_at(data, at), u32_at(data, at + 4)) else { break };
        table.push((end as usize, state, f64_at(data, at + 8)));
    }
    // Entries are laid out in order of their end offsets, which the table need not follow.
    table.sort_by_key(|&(end, ..)| end);
    let mut out = Vec::new();
    let mut prev_end = 0usize;
    for (i, (end, state, time)) in table.into_iter().enumerate() {
        let abs_end = V2_HEADER + end;
        if abs_end > trailer {
            warn.push(format!("entry {i}: end offset {end} is past the data area"));
            continue;
        }
        let abs_start = V2_HEADER + prev_end.checked_add(3).map_or(usize::MAX, |n| n & !3);
        // An entry too short for its preamble is an empty (deleted) record.
        let payload = data.get(abs_start.saturating_add(V2_PREAMBLE)..abs_end).unwrap_or(&[]);
        out.push(Raw { offset: abs_start as u64, time, state, payload });
        prev_end = end;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *data.get(*pos)?;
        *pos += 1;
        // The tenth byte may only carry the top bit of a u64.
        if i == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A fixed 64-bit field is an integer or a double; doubles that land on a plausible Mac
/// absolute time (2004-2033) are by far the most common in Biome, so those are shown as such.
fn fixed64(raw: u64) -> Value {
    let double = f64::from_bits(raw);
    match serde_json::Number::from_f64(double) {
        Some(n) if (1.0e8..1.0e9).contains(&double) => Value::Number(n),
        _ => raw.into(),
    }
}

/// A length-delimited field: a nested message if it parses strictly, else text, else hex.
/// Short plain text ("hi" is a valid tag, varint pair) often parses as a message by accident,
/// while real messages almost always contain control bytes (tags 0x08, 0x0a, 0x12...), so text
/// without any control character is taken as text first.
fn bytes_field(bytes: &[u8], depth: usize, texts: &mut Vec<String>) -> Value {
    let plain = std::str::from_utf8(bytes).is_ok_and(|s| !s.chars().any(char::is_control));
    if depth < MAX_DEPTH && !plain {
        let mark = texts.len();
        if let Some(map) = message(bytes, depth + 1, texts).filter(|m| !m.is_empty()) {
            return Value::Object(map);
        }
        texts.truncate(mark);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            if !s.is_empty() {
                texts.push(s.to_string());
            }
            s.into()
        }
        Err(_) => hex(bytes).into(),
    }
}

/// Parses the whole slice as one message, or returns `None` if any byte does not fit.
fn message(data: &[u8], depth: usize, texts: &mut Vec<String>) -> Option<Map<String, Value>> {
    let mut map = Map::new();
    let mut pos = 0;
    while pos < data.len() {
        let tag = varint(data, &mut pos)?;
        if tag >> 3 == 0 {
            return None;
        }
        let value = match tag & 7 {
            0 => varint(data, &mut pos)?.into(),
            1 => {
                let raw = data.get(pos..pos.checked_add(8)?)?;
                pos += 8;
                fixed64(u64::from_le_bytes(raw.try_into().ok()?))
            }
            2 => {
                let len = usize::try_from(varint(data, &mut pos)?).ok()?;
                let end = pos.checked_add(len)?;
                let bytes = data.get(pos..end)?;
                pos = end;
                bytes_field(bytes, depth, texts)
            }
            5 => {
                let raw = data.get(pos..pos.checked_add(4)?)?;
                pos += 4;
                u32::from_le_bytes(raw.try_into().ok()?).into()
            }
            _ => return None, // groups and reserved wire types
        };
        match map.get_mut(&(tag >> 3).to_string()) {
            // Repeated field. Arrays are never produced for anything else.
            Some(Value::Array(items)) => items.push(value),
            Some(existing) => *existing = Value::Array(vec![existing.take(), value]),
            None => {
                map.insert((tag >> 3).to_string(), value);
            }
        }
    }
    Some(map)
}

/// Decodes a schema-less protobuf message into nested maps keyed by field number, plus its text
/// values in wire order. `None` if the payload is not a well-formed message.
fn decode(payload: &[u8]) -> Option<(Map<String, Value>, Vec<String>)> {
    let mut texts = Vec::new();
    message(payload, 0, &mut texts).map(|map| (map, texts))
}

fn summary(texts: &[String]) -> String {
    let joined = texts.iter().take(SUMMARY_TEXTS).map(String::as_str).collect::<Vec<_>>().join(" | ");
    match joined.char_indices().nth(SUMMARY_CHARS) {
        Some((cut, _)) => joined[..cut].to_string(),
        None => joined,
    }
}

/// The stream directory: the component after the scope (`public`, `restricted`) under `streams`.
fn stream_name(path: &str) -> &str {
    let mut parts = path.split('/').skip_while(|p| *p != "streams");
    parts.nth(2).unwrap_or("")
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    let mut warnings = Vec::new();
    let entries = if data.starts_with(MAGIC) {
        v2(data, &mut warnings)?
    } else if data.get(V1_HEADER - 4..V1_HEADER) == Some(MAGIC) {
        v1(data, &mut warnings)
    } else {
        return Err(Error::skipped("not a SEGB file"));
    };
    let (stream, user) = (stream_name(input.path), user_from_path(input.path));
    for raw in entries {
        let state = match raw.state {
            1 => "written",
            3 => "deleted",
            _ => "unknown",
        };
        let (fields, summary) = match decode(raw.payload) {
            _ if raw.payload.is_empty() => (Value::Object(Map::new()), String::new()),
            Some((map, texts)) => (Value::Object(map), summary(&texts)),
            None => {
                // A deleted entry's payload is wiped, so failing to decode it is expected.
                if raw.state != 3 {
                    warnings.push(format!("offset {}: payload is not a protobuf message", raw.offset));
                }
                (Value::Object(Map::from_iter([("raw".to_string(), hex(raw.payload).into())])), String::new())
            }
        };
        let time = or_warn(sink, "record time", raw.time, mac_time);
        sink.emit(Loc::Offset(raw.offset), &Entry { time, stream, state, user, fields, summary })?;
    }
    for warning in warnings {
        sink.warn(warning);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Users/alice/Library/Biome/streams/public/App.InFocus/local/1234567";

    #[test]
    fn parses_v1_and_v2() {
        insta::assert_snapshot!("v1", run(&ARTIFACT, PATH, &fixture("biome/segb_v1.bin"), 0));
        insta::assert_snapshot!("v2", run(&ARTIFACT, PATH, &fixture("biome/segb_v2.bin"), 0));
    }

    #[test]
    fn v2_trailer_in_any_order_is_read() {
        // Two entries, each an 8-byte preamble and a message, at 32..44 and 44..56: the
        // second starts on a 4-byte boundary that is not an 8-byte one, as real files do.
        let mut data = b"SEGB".to_vec();
        data.extend(2u32.to_le_bytes());
        data.resize(V2_HEADER, 0);
        data.extend([0; 8]);
        data.extend([0x0a, 2, b'h', b'i']);
        data.extend([0; 8]);
        data.extend([0x0a, 2, b'y', b'o']);
        let entry = |end: u32| {
            [end.to_le_bytes().to_vec(), 1u32.to_le_bytes().to_vec(), 1.0f64.to_le_bytes().to_vec()].concat()
        };
        let mut sorted = data.clone();
        sorted.extend(entry(12));
        sorted.extend(entry(24));
        data.extend(entry(24));
        data.extend(entry(12));
        let (a, b) = (run(&ARTIFACT, PATH, &sorted, 0), run(&ARTIFACT, PATH, &data, 0));
        assert_eq!(a.matches("\"stream\":").count(), 2, "{a}");
        assert_eq!(a, b, "the table order must not matter");
    }

    #[test]
    fn out_of_range_times_are_dropped_with_a_warning() {
        let mut data = fixture("biome/segb_v2.bin");
        let at = data.len() - V2_TRAILER_ENTRY + 8;
        data[at..at + 8].copy_from_slice(&5.0e10f64.to_le_bytes());
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert!(out.contains("is not a valid time"), "{out}");
    }

    #[test]
    fn other_files_are_skipped() {
        for data in [&b"bplist00"[..], b"", b"<?xml version=\"1.0\"?>", &[0u8; 100]] {
            assert!(run(&ARTIFACT, PATH, data, 0).contains("--- skipped: not a SEGB"));
        }
    }

    #[test]
    fn stream_from_path() {
        assert_eq!(
            stream_name("private/var/db/biome/streams/restricted/Notification.Usage/remote/ABCD/99"),
            "Notification.Usage"
        );
        assert_eq!(stream_name("somewhere/else"), "");
    }

    /// Never panics or loops on damaged files: every prefix, and seeded random byte flips.
    #[test]
    fn damaged_files_return() {
        for name in ["biome/segb_v1.bin", "biome/segb_v2.bin"] {
            let data = fixture(name);
            for len in 0..=data.len() {
                run(&ARTIFACT, PATH, &data[..len], 0);
            }
            let mut state = 0x9e3779b97f4a7c15u64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            for _ in 0..300 {
                let mut copy = data.clone();
                for _ in 0..1 + next() % 4 {
                    let at = (next() % copy.len() as u64) as usize;
                    copy[at] = next() as u8;
                }
                run(&ARTIFACT, PATH, &copy, 0);
            }
        }
    }

    fn texts(payload: &[u8]) -> Option<(String, Vec<String>)> {
        decode(payload).map(|(m, t)| (Value::Object(m).to_string(), t))
    }

    #[test]
    fn protobuf_basics() {
        // field 1 varint 150, field 2 string "hi", field 3 nested {1: 1}, field 4 fixed32, field 2 again
        let msg = [0x08, 0x96, 0x01, 0x12, 2, b'h', b'i', 0x1a, 2, 0x08, 0x01, 0x25, 1, 0, 0, 0, 0x12, 1, b'x'];
        let (json, t) = texts(&msg).unwrap();
        assert_eq!(json, r#"{"1":150,"2":["hi","x"],"3":{"1":1},"4":1}"#);
        assert_eq!(t, ["hi", "x"]);
        // Invalid UTF-8 that does not parse as a message is hex.
        let (json, _) = texts(&[0x0a, 2, 0xff, 0xfe]).unwrap();
        assert_eq!(json, r#"{"1":"fffe"}"#);
    }

    #[test]
    fn protobuf_rejects_damage() {
        // Varint overflow: eleven continuation bytes, and a tenth byte above 1.
        assert!(decode(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).is_none());
        assert!(decode(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]).is_none());
        assert!(decode(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).is_some());
        // Truncated length-delimited field, truncated varint, truncated fixed fields.
        assert!(decode(&[0x0a, 5, b'a']).is_none());
        assert!(decode(&[0x0a]).is_none());
        assert!(decode(&[0x08, 0x80]).is_none());
        assert!(decode(&[0x09, 1, 2, 3]).is_none());
        assert!(decode(&[0x0d, 1, 2, 3]).is_none());
        // Length larger than usize can address, field number 0, groups.
        assert!(decode(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_none());
        assert!(decode(&[0x00, 0x01]).is_none());
        assert!(decode(&[0x0b, 0x0c]).is_none());
    }

    #[test]
    fn protobuf_zero_length_fields() {
        let (json, t) = texts(&[0x0a, 0x00, 0x10, 0x00]).unwrap();
        assert_eq!(json, r#"{"1":"","2":0}"#);
        assert!(t.is_empty());
        assert!(decode(b"").unwrap().0.is_empty());
    }

    #[test]
    fn protobuf_nesting_is_depth_limited() {
        // 40 levels of `{1: <next>}` around the string "leaf"; the string hangs below the last message.
        let mut payload = vec![0x0a, 4, b'l', b'e', b'a', b'f'];
        for _ in 0..40 {
            let mut outer = vec![0x0a, payload.len() as u8];
            outer.extend(&payload);
            payload = outer;
        }
        let (map, _) = decode(&payload).unwrap();
        let mut depth = 0;
        let mut value = &Value::Object(map);
        while let Some(next) = value.get("1") {
            depth += 1;
            value = next;
        }
        assert!(depth <= MAX_DEPTH + 1, "{depth}");
        assert!(value.is_string(), "{value}");
    }

    #[test]
    fn summary_is_capped_on_char_boundaries() {
        let long = "é".repeat(300);
        assert_eq!(summary(&[long, "b".into()]).chars().count(), SUMMARY_CHARS);
        assert_eq!(summary(&["a".into(), "b".into()]), "a | b");
    }

    /// Needs real files, which must not live in the repository. Place copies under
    /// the directory named by `NIXCAVATE_ACTIVITY_CORPUS` (any depth) and run
    /// `cargo test -p nixcavate-artifacts -- --ignored real_corpus`.
    #[test]
    #[ignore]
    fn real_corpus_biome() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(std::path::Path::new(&std::env::var("NIXCAVATE_ACTIVITY_CORPUS").unwrap_or_default()), &mut files);
        for file in files {
            let Ok(data) = std::fs::read(&file) else { continue };
            if data.starts_with(MAGIC) || data.get(V1_HEADER - 4..V1_HEADER) == Some(MAGIC) {
                let out = run(&ARTIFACT, PATH, &data, 0);
                assert!(!out.contains("--- failed"), "{}", file.display());
            }
        }
    }
}

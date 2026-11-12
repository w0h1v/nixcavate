//! Apple System Log (ASL) binary databases (`/var/log/asl/*.asl`, `DiagnosticMessages`), written
//! by syslogd before the Unified Log. Format: libyal dtformats, "Apple System Log (ASL) file
//! format", version 2, big-endian throughout. The layout was also checked against real files with
//! `syslog -f <file> -F raw`.
//!
//! File: an 80-byte header (`ASL DB`, version, first record offset at 16), then string records
//! (u16 type, u32 length, NUL-terminated text) and records interleaved. Record: u16, u32 length of
//! the rest, u64 next-record offset, u64 message id, i64 seconds, u32 nanoseconds, u16 level,
//! u16 flags, u32 pid/uid/gid/read-uid/read-gid/ref-pid, u32 count of key and value items, six
//! string references (host, sender, facility, message, ref proc, session), the key and value
//! references, and a u64 previous-record offset. A reference is 0 (absent), an offset of a string
//! record, or, with the top bit set, an inline string: that byte's low 7 bits give the length
//! and the next 7 bytes the text. Records are found by following the next-record chain.

use crate::common::syslog::timeline_message;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::ser::{Serialize, SerializeMap, Serializer};
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "asl",
    "Apple System Log binary databases",
    Category::Logs,
    MACOS,
    &["private/var/log/asl/*.asl", "private/var/log/asl/**/*.asl", "private/var/log/DiagnosticMessages/*.asl"],
    parse,
);

const MAGIC: &[u8] = b"ASL DB\0\0\0\0\0\0";
const HEADER_SIZE: usize = 80;
/// Everything in a record before the key and value references.
const FIXED_SIZE: usize = 114;
const NO_READ_ID: u32 = u32::MAX;
/// Text copied out of the strings may be this many times the file size.
const TEXT_PER_BYTE: usize = 16;

/// The additional key/value pairs of a record, written as a JSON object.
struct Extra<'a>(Vec<(Cow<'a, str>, Cow<'a, str>)>);

impl Serialize for Extra<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(serde::Serialize)]
struct Message<'a> {
    /// `None` when the stored seconds are outside 1677-2262.
    time: Option<Timestamp>,
    level: u16,
    level_name: Option<&'static str>,
    log_host: Cow<'a, str>,
    sender: Cow<'a, str>,
    facility: Cow<'a, str>,
    pid: i32,
    uid: i32,
    gid: i32,
    /// ASL's access-control ids; `None` when unset (-1).
    read_uid: Option<u32>,
    read_gid: Option<u32>,
    message: Cow<'a, str>,
    ref_pid: i32,
    ref_proc: Cow<'a, str>,
    session: Cow<'a, str>,
    extra: Extra<'a>,
}

impl Record for Message<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|t| Event::new(t, "log", timeline_message(&self.sender, &self.message))).into_iter()
    }
}

fn level_name(level: u16) -> Option<&'static str> {
    ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"].get(usize::from(level)).copied()
}

fn be<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    // Callers have checked the length; a short slice reads as zeros rather than panicking.
    let mut out = [0u8; N];
    if let Some(bytes) = data.get(at..at.saturating_add(N)) {
        out.copy_from_slice(bytes);
    }
    out
}

/// The text a string reference points at, or `None` when it points outside the file.
fn string(data: &[u8], reference: u64) -> Option<Cow<'_, str>> {
    if reference == 0 {
        return Some(Cow::Borrowed(""));
    }
    if reference >> 63 == 1 {
        let bytes = reference.to_be_bytes();
        let len = usize::from(bytes[0] & 0x7f).min(7);
        return Some(Cow::Owned(String::from_utf8_lossy(&bytes[1..=len]).into_owned()));
    }
    let at = usize::try_from(reference).ok()?;
    let len = usize::try_from(u32::from_be_bytes(be(data, at.checked_add(2)?))).ok()?;
    let start = at.checked_add(6)?;
    let text = data.get(start..start.checked_add(len)?.min(data.len()))?;
    let text = &text[..memchr::memchr(0, text).unwrap_or(text.len())];
    Some(String::from_utf8_lossy(text))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if !data.starts_with(MAGIC) || data.len() < HEADER_SIZE {
        return Err(Error::format("not an ASL database"));
    }
    let version = u32::from_be_bytes(be(data, 12));
    if version != 2 {
        sink.warn(format!("ASL version {version} is not the documented version 2; fields may be wrong"));
    }
    let mut offset = u64::from_be_bytes(be(data, 16));
    let mut text_budget = data.len().saturating_mul(TEXT_PER_BYTE);
    while offset != 0 {
        let Some(at) = usize::try_from(offset).ok().filter(|&at| at >= HEADER_SIZE) else {
            sink.warn(format!("record offset {offset} is outside the file"));
            break;
        };
        let Some(fixed) = at.checked_add(FIXED_SIZE).and_then(|end| data.get(at..end)) else {
            sink.warn(format!("offset {offset}: record is cut off"));
            break;
        };
        let u32_at = |p: usize| u32::from_be_bytes(be(fixed, p));
        // Items are keys and values alternating; the count is bounded by the bytes present.
        let items = usize::try_from(u32_at(62)).unwrap_or(usize::MAX);
        let items_end = items.checked_mul(8).and_then(|n| n.checked_add(at + FIXED_SIZE));
        let Some(items_bytes) = items_end.and_then(|end| data.get(at + FIXED_SIZE..end)) else {
            sink.warn(format!("offset {offset}: record is cut off"));
            break;
        };
        if items % 2 != 0 {
            sink.warn(format!("offset {offset}: odd item count {items}; the last key has no value"));
        }
        let mut bad_reference = false;
        let mut text = |reference: u64| {
            let text = string(data, reference).unwrap_or_else(|| {
                bad_reference = true;
                Cow::Borrowed("")
            });
            // Many items may point at one long string: stop copying it once the output would
            // dwarf the file.
            text_budget = text_budget.saturating_sub(text.len());
            if text_budget == 0 {
                return Cow::Borrowed("");
            }
            text
        };
        let refs: [u64; 6] = std::array::from_fn(|i| u64::from_be_bytes(be(fixed, 66 + 8 * i)));
        let [log_host, sender, facility, message, ref_proc, session] = refs.map(&mut text);
        let extra = items_bytes
            .chunks_exact(16)
            .map(|pair| (text(u64::from_be_bytes(be(pair, 0))), text(u64::from_be_bytes(be(pair, 8)))))
            .collect();
        let level = u16::from_be_bytes(be(fixed, 34));
        let nanos = u32::from_be_bytes(be(fixed, 30)).min(999_999_999);
        let read_id = |p: usize| Some(u32_at(p)).filter(|&id| id != NO_READ_ID);
        let record = Message {
            time: Timestamp::checked(i64::from_be_bytes(be(fixed, 22)), nanos, Precision::Nanos, Basis::Recorded),
            level,
            level_name: level_name(level),
            log_host,
            sender,
            facility,
            pid: u32_at(38) as i32,
            uid: u32_at(42) as i32,
            gid: u32_at(46) as i32,
            read_uid: read_id(50),
            read_gid: read_id(54),
            message,
            ref_pid: u32_at(58) as i32,
            ref_proc,
            session,
            extra: Extra(extra),
        };
        if record.time.is_none() {
            sink.warn(format!("offset {offset}: record time is outside 1677-2262; left empty"));
        }
        if text_budget == 0 {
            sink.warn(format!("offset {offset}: strings shared by many items exceed the output limit; stopping"));
            break;
        }
        if bad_reference {
            sink.warn(format!("offset {offset}: a string reference points outside the file"));
        }
        sink.emit(Loc::Offset(offset), &record)?;
        let next = u64::from_be_bytes(be(fixed, 6));
        // The chain only ever moves forward, past the end of this record: anything else is a
        // cycle, or records overlapping so that each claims the bytes of the next.
        let end = (at + FIXED_SIZE + items_bytes.len()) as u64;
        if next != 0 && next <= offset {
            sink.warn(format!("offset {offset}: next record offset {next} does not advance; stopping"));
            break;
        }
        if next != 0 && next < end {
            sink.warn(format!("offset {offset}: next record at {next} overlaps this record (ends at {end}); stopping"));
            break;
        }
        offset = next;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "private/var/log/asl/2024.03.10.G80.asl";

    /// `test_files/asl/generate.py` writes this file from the published layout.
    #[test]
    fn synthetic_database() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("asl/sample.asl"), 0));
    }

    #[test]
    fn empty_and_foreign_files() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, PATH, &[7u8; 300], 0).contains("failed: not an ASL database"));
    }

    #[test]
    fn a_record_chain_that_loops_stops() {
        let mut data = fixture("asl/sample.asl");
        let first = u64::from_be_bytes(be(&data, 16)) as usize;
        data[first + 6..first + 14].copy_from_slice(&(first as u64).to_be_bytes());
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert_eq!(out.matches("\"sender\"").count(), 1, "{out}");
        assert!(out.contains("does not advance"));
    }

    /// Records every 128 bytes, each declaring items that cover all the bytes after it.
    fn overlapping_records(size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        data[..12].copy_from_slice(MAGIC);
        data[12..16].copy_from_slice(&2u32.to_be_bytes());
        data[16..24].copy_from_slice(&80u64.to_be_bytes());
        let mut at = 80usize;
        while at + FIXED_SIZE + 8 <= size {
            let next = if at + 128 + FIXED_SIZE + 8 <= size { at + 128 } else { 0 };
            data[at + 6..at + 14].copy_from_slice(&(next as u64).to_be_bytes());
            let items = ((size - at - FIXED_SIZE) / 8) as u32 & !1;
            data[at + 62..at + 66].copy_from_slice(&items.to_be_bytes());
            at += 128;
        }
        data
    }

    #[test]
    fn overlapping_records_cannot_amplify() {
        let data = overlapping_records(64 << 10);
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert!(out.len() < data.len() * 64, "{} bytes out for {} in", out.len(), data.len());
        assert!(out.contains("overlaps"), "{}", &out[out.len().saturating_sub(300)..]);
    }

    #[test]
    fn shared_strings_cannot_amplify() {
        // One big string record referenced by every item of the next record.
        let mut data = vec![0u8; 8192];
        data[..12].copy_from_slice(MAGIC);
        data[12..16].copy_from_slice(&2u32.to_be_bytes());
        data[16..24].copy_from_slice(&1000u64.to_be_bytes());
        data[80..82].copy_from_slice(&1u16.to_be_bytes());
        data[82..86].copy_from_slice(&1000u32.to_be_bytes());
        data[86..1000].fill(b'x');
        data[1000 + 62..1000 + 66].copy_from_slice(&700u32.to_be_bytes());
        for n in 0..700 {
            data[1000 + FIXED_SIZE + 8 * n..][..8].copy_from_slice(&80u64.to_be_bytes());
        }
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert!(out.len() < data.len() * 64, "{} bytes out", out.len());
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        let data = fixture("asl/sample.asl");
        for len in 0..data.len() {
            run(&ARTIFACT, PATH, &data[..len], 0);
        }
        for i in 0..data.len() {
            for mask in [0xff, 0x80, 0x01] {
                let mut flipped = data.clone();
                flipped[i] ^= mask;
                run(&ARTIFACT, PATH, &flipped, 0);
            }
        }
    }
}

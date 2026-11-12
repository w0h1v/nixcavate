//! Reading property lists from evidence safely.
//!
//! A hostile plist can nest containers until dropping the parsed tree overflows the stack
//! (which aborts the process: it cannot be caught), or, in the binary format, let objects
//! share children so that a few hundred bytes expand to gigabytes. The input is checked for
//! both before the `plist` crate sees it. Every plist read in nixcavate goes through here.

use nixcavate_core::{Error, Result};
use plist::Value;
use std::io::Cursor;

/// Containers nested deeper than this are refused (the `Value` tree is dropped recursively).
const MAX_DEPTH: usize = 256;

/// Parses a property list (XML, binary or ASCII). The input is checked first: a hostile file
/// can nest containers until the stack overflows, or (binary) let objects share children so a
/// few hundred bytes expand to gigabytes. Every plist read goes through here.
pub fn parse(data: &[u8]) -> Result<Value> {
    if data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    if data.starts_with(b"bplist00") {
        check_binary(data)?;
    } else {
        check_text_depth(data)?;
    }
    Value::from_reader(Cursor::new(data)).map_err(|_| Error::format("not a property list"))
}

fn too_deep() -> Error {
    Error::format(format!("property list nested deeper than {MAX_DEPTH} levels"))
}

/// Nesting depth of an XML or ASCII (OpenStep) plist, by a scan of its markup.
fn check_text_depth(data: &[u8]) -> Result<()> {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    let mut depth = 0usize;
    let mut i = start;
    if data[start..].starts_with(b"<") || data[start..].starts_with(b"\xEF\xBB\xBF<") {
        while let Some(at) = memchr::memchr(b'<', &data[i..]) {
            let tag = &data[i + at..];
            // Comments, CDATA and processing instructions end at their own terminator.
            let end = [(&b"<!--"[..], &b"-->"[..]), (b"<![CDATA[", b"]]>"), (b"<?", b"?>")]
                .iter()
                .find(|(open, _)| tag.starts_with(open))
                .map_or(b">".as_slice(), |(_, close)| close);
            let Some(len) = tag.windows(end.len()).position(|w| w == end) else { break };
            i += at + len + end.len();
            // The name without its leading `<`.
            let tag = &tag[1..len.max(1)];
            if tag.starts_with(b"/") {
                depth = depth.saturating_sub(1);
            } else if !tag.starts_with(b"!") && !tag.starts_with(b"?") && !tag.ends_with(b"/") {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(too_deep());
                }
            }
        }
        return Ok(());
    }
    // ASCII: brackets outside quoted strings and comments.
    let (mut quoted, mut escaped) = (false, false);
    while i < data.len() {
        let b = data[i];
        i += 1;
        if quoted {
            (quoted, escaped) = (escaped || b != b'"', !escaped && b == b'\\');
        } else if b == b'"' {
            quoted = true;
        } else if b == b'/' && data.get(i) == Some(&b'*') {
            i = data[i..].windows(2).position(|w| w == b"*/").map_or(data.len(), |n| i + n + 2);
        } else if b == b'/' && data.get(i) == Some(&b'/') {
            i = memchr::memchr(b'\n', &data[i..]).map_or(data.len(), |n| i + n);
        } else if b == b'(' || b == b'{' {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(too_deep());
            }
        } else if b == b')' || b == b'}' {
            depth = depth.saturating_sub(1);
        }
    }
    Ok(())
}

/// Walks the object graph of a binary plist without building it, adding up what the plist
/// crate would build: objects shared by several parents count once per parent. Refuses
/// graphs that are too deep, cyclic, or larger than [`BUDGET_PER_BYTE`] times the file.
fn check_binary(data: &[u8]) -> Result<()> {
    let bad = || Error::format("not a property list");
    let trailer = data.len().checked_sub(32).filter(|&t| t >= 8).map(|t| &data[t..]).ok_or_else(bad)?;
    let (offset_size, ref_size) = (usize::from(trailer[6]), usize::from(trailer[7]));
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return Err(bad());
    }
    let count = be_int(trailer, 8, 8).ok_or_else(bad)?;
    let root = be_int(trailer, 16, 8).ok_or_else(bad)?;
    let table = be_int(trailer, 24, 8).ok_or_else(bad)?;
    let table_end = count.checked_mul(offset_size).and_then(|n| n.checked_add(table)).ok_or_else(bad)?;
    if table_end > data.len() - 32 || root >= count {
        return Err(bad());
    }
    let mut graph = Graph {
        data,
        table: &data[table..table_end],
        offset_size,
        ref_size,
        memo: vec![Memo::Unseen; count],
        budget: (data.len() as u64).saturating_mul(BUDGET_PER_BYTE).max(MIN_BUDGET),
    };
    graph.visit(root, 1).map(drop)
}

/// A binary plist may expand to this many objects and bytes per input byte, at least
/// [`MIN_BUDGET`]. Real files share little: they stay far below it.
const BUDGET_PER_BYTE: u64 = 64;
const MIN_BUDGET: u64 = 4096;

/// A big-endian unsigned integer of `size` bytes at `at`.
fn be_int(bytes: &[u8], at: usize, size: usize) -> Option<usize> {
    let bytes = bytes.get(at..at.checked_add(size)?)?;
    usize::try_from(bytes.iter().fold(0u64, |n, &b| n << 8 | u64::from(b))).ok()
}

#[derive(Clone, Copy)]
enum Memo {
    Unseen,
    Open,
    Done(u64),
}

struct Graph<'a> {
    data: &'a [u8],
    table: &'a [u8],
    offset_size: usize,
    ref_size: usize,
    memo: Vec<Memo>,
    budget: u64,
}

impl Graph<'_> {
    /// The expanded size of object `index`, `depth` levels below the root.
    fn visit(&mut self, index: usize, depth: usize) -> Result<u64> {
        let bad = || Error::format("not a property list");
        if depth > MAX_DEPTH {
            return Err(too_deep());
        }
        match self.memo.get(index).copied().ok_or_else(bad)? {
            Memo::Done(cost) => return Ok(cost),
            Memo::Open => return Err(Error::format("property list contains a cycle")),
            Memo::Unseen => self.memo[index] = Memo::Open,
        }
        let offset = be_int(self.table, index * self.offset_size, self.offset_size).ok_or_else(bad)?;
        let marker = *self.data.get(offset).ok_or_else(bad)?;
        let (kind, mut len, mut at) = (marker >> 4, usize::from(marker & 15), offset + 1);
        if len == 15 && matches!(kind, 4 | 5 | 6 | 10 | 13) {
            let size_marker = *self.data.get(at).ok_or_else(bad)?;
            let size = 1usize << (size_marker & 7);
            len = be_int(self.data, at + 1, size).ok_or_else(bad)?;
            at += 1 + size;
        }
        let mut cost = 1u64;
        match kind {
            // `len` is read from the file and may be any 64-bit value.
            4 | 5 => cost = cost.saturating_add(len as u64),
            6 => cost = cost.saturating_add((len as u64).saturating_mul(2)),
            10 | 13 => {
                let refs = if kind == 13 { len.checked_mul(2) } else { Some(len) }.ok_or_else(bad)?;
                let end = refs.checked_mul(self.ref_size).and_then(|n| n.checked_add(at)).ok_or_else(bad)?;
                if end > self.data.len() {
                    return Err(bad());
                }
                for n in 0..refs {
                    let child = be_int(self.data, at + n * self.ref_size, self.ref_size).ok_or_else(bad)?;
                    cost = cost.saturating_add(self.visit(child, depth + 1)?);
                    if cost > self.budget {
                        return Err(Error::format("property list expands far beyond its size"));
                    }
                }
            }
            _ => {}
        }
        self.memo[index] = Memo::Done(cost);
        Ok(cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_xml_plist_is_not_mistaken_for_a_deep_one() {
        let keys: String =
            (0..2_000).map(|n| format!("<key>k{n}</key><array><integer>{n}</integer></array>")).collect();
        let xml =
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{keys}</dict></plist>");
        let value = parse(xml.as_bytes()).unwrap();
        assert_eq!(value.as_dictionary().unwrap().len(), 2_000);
    }

    /// Found by the `btm` fuzz target: a declared string length near 2^64 overflowed the
    /// cost arithmetic.
    #[test]
    fn a_forged_length_is_an_error_not_a_panic() {
        let crash = include_bytes!("../../../test_files/plist/fuzz-length-overflow.bplist");
        assert!(parse(crash).is_err());
    }

    #[test]
    fn a_deep_xml_plist_is_refused() {
        let xml = format!("<plist>{}{}</plist>", "<array>".repeat(300), "</array>".repeat(300));
        assert!(parse(xml.as_bytes()).is_err());
        let ok = format!("<plist>{}{}</plist>", "<array>".repeat(200), "</array>".repeat(200));
        assert!(parse(ok.as_bytes()).is_ok());
    }
}

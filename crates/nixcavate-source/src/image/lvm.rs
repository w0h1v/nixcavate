//! LVM2 physical volumes: the logical volumes that are linear, read through to their extents.
//!
//! Written from the LVM2 text format (`lib/format_text/layout.h` in the LVM2 source): a label
//! (`LABELONE`, `LVM2 001`) in one of the first four sectors points at the physical volume
//! header (uuid, data areas, metadata areas); a metadata area holds a header and a circular
//! buffer with the volume group description as a text config tree. The first `raw_locn` of the
//! header is the committed copy.
//!
//! Only linear logical volumes are read: segments of type `striped` with one stripe. Thin,
//! RAID, mirror, cache and snapshot volumes, and striped sets, are named in a note and left out.
//! The text checksums are not verified: the text is parsed defensively instead.
//!
//! Nothing here trusts the disk: sizes and offsets are checked, the text and its nesting are
//! capped, and every logical volume is a table of segments that must tile it exactly.

use super::{Part, Shared};
use nixcavate_fs::{le32, le64, ReadAt};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

const SECTOR: u64 = 512;
const MDA_MAGIC: &[u8; 16] = b" LVM2 x[5A%r0N*>";
/// The metadata text of one area, as the largest we will read.
const MAX_TEXT: u64 = 16 << 20;
const MAX_DEPTH: usize = 16;
const MAX_LVS: usize = 4096;
const MAX_SEGMENTS: usize = 65_536;
/// Data areas and metadata areas examined per physical volume.
const MAX_AREAS: usize = 64;
/// Keys and values in one text: bounds the memory a hostile text can take.
const MAX_ENTRIES: usize = 1 << 19;
const MAX_NAME: usize = 128;

/// A linear logical volume, readable as a disk of `len` bytes.
pub struct LogicalVolume {
    /// `<volume group>-<logical volume>` restricted to a safe character set.
    pub name: String,
    pub reader: Shared,
    pub len: u64,
}

/// Reads the logical volumes of the physical volumes `pvs` (partition index and contents).
/// Anything that cannot be read or is not supported is described in the notes.
pub fn open(pvs: Vec<(usize, Part)>) -> (Vec<LogicalVolume>, Vec<String>) {
    let mut notes = Vec::new();
    let mut physical = Vec::new();
    let mut copies = Vec::new();
    for (index, part) in pvs {
        let part = Arc::new(part);
        let label = match read_label(&part) {
            Ok(label) => label,
            Err(why) => {
                notes.push(format!("partition {index}: LVM2 physical volume skipped: {why}"));
                continue;
            }
        };
        match read_copy(&part, &label.areas) {
            Ok(copy) => copies.push(copy),
            Err(why) => notes.push(format!("partition {index}: LVM2 metadata not read: {why}")),
        }
        // Even with unreadable metadata its extents can be reached through another copy.
        physical.push(Pv { uuid: label.uuid, part });
    }
    // Every physical volume carries a copy of its group's metadata: keep the newest.
    let mut newest: Vec<Copy> = Vec::new();
    for copy in copies {
        match newest.iter_mut().find(|c| c.key == copy.key) {
            Some(held) if held.seqno >= copy.seqno => {}
            Some(held) => *held = copy,
            None => newest.push(copy),
        }
    }
    let by_uuid: HashMap<&str, &Pv> = physical.iter().map(|pv| (pv.uuid.as_str(), pv)).collect();
    let mut names = HashSet::new();
    let mut volumes = Vec::new();
    for copy in &newest {
        volume_group(copy, &by_uuid, &mut names, &mut volumes, &mut notes);
    }
    (volumes, notes)
}

/// A physical volume found in the image.
struct Pv {
    /// The uuid from the PV header, without dashes.
    uuid: String,
    part: Arc<Part>,
}

struct Label {
    uuid: String,
    /// Metadata areas: (offset, size), size 0 meaning up to the end of the device.
    areas: Vec<(u64, u64)>,
}

/// Reads `len` bytes at `at`, which must lie inside `part`.
fn read(part: &Part, at: u64, len: u64) -> Result<Vec<u8>, String> {
    if len > MAX_TEXT || at.checked_add(len).is_none_or(|end| end > part.size()) {
        return Err(format!("{len} bytes at {at} are outside the volume"));
    }
    let mut buf = vec![0u8; usize::try_from(len).map_err(|_| "read too large")?];
    part.read_at(at, &mut buf).map_err(|e| format!("read failed: {e}"))?;
    Ok(buf)
}

fn read_label(part: &Part) -> Result<Label, String> {
    let head = read(part, 0, part.size().min(4 * SECTOR))?;
    let sector = (0..4usize)
        .find(|s| {
            head.get(s * 512..s * 512 + 32).is_some_and(|l| l.starts_with(b"LABELONE") && &l[24..32] == b"LVM2 001")
        })
        .ok_or("no LVM2 label in the first four sectors")?;
    let header_at =
        (sector as u64 * SECTOR).checked_add(u64::from(le32(&head, sector * 512 + 20))).ok_or("bad label offset")?;
    let block = read(part, header_at, part.size().saturating_sub(header_at).min(4096))?;
    if block.len() < 40 {
        return Err("truncated physical volume header".into());
    }
    let uuid: String = String::from_utf8_lossy(&block[..32]).trim_matches(['\0', ' ']).replace('-', "");
    let mut at = 40;
    area_list(&block, &mut at)?; // data areas: the metadata gives the extents' position
    let areas = area_list(&block, &mut at)?;
    Ok(Label { uuid, areas })
}

/// A list of (offset, size) pairs ended by an all-zero pair.
fn area_list(block: &[u8], at: &mut usize) -> Result<Vec<(u64, u64)>, String> {
    let mut out = Vec::new();
    for _ in 0..=MAX_AREAS {
        let entry = block.get(*at..*at + 16).ok_or("truncated area list")?;
        *at += 16;
        let (offset, size) = (le64(entry, 0), le64(entry, 8));
        if offset == 0 && size == 0 {
            return Ok(out);
        }
        out.push((offset, size));
    }
    Err("area list does not end".into())
}

/// One copy of a volume group's metadata.
struct Copy {
    /// What groups copies of the same volume group.
    key: String,
    name: String,
    seqno: u64,
    body: Section,
}

fn read_copy(part: &Part, areas: &[(u64, u64)]) -> Result<Copy, String> {
    let mut last = String::from("no metadata area");
    for &(start, size) in areas {
        match read_metadata(part, start, size) {
            Ok(Some(text)) => match parse(&text).and_then(volume_group_of) {
                Ok(copy) => return Ok(copy),
                Err(why) => last = why,
            },
            Ok(None) => last = "the metadata area holds no committed metadata".into(),
            Err(why) => last = why,
        }
    }
    Err(last)
}

/// The text of the committed metadata of the area at `start`, following the circular buffer.
fn read_metadata(part: &Part, start: u64, listed: u64) -> Result<Option<Vec<u8>>, String> {
    let header = read(part, start, SECTOR)?;
    if header[4..20] != MDA_MAGIC[..] {
        return Err("bad metadata area magic".into());
    }
    if le32(&header, 20) != 1 {
        return Err("unknown metadata area version".into());
    }
    let size = if listed != 0 { listed } else { le64(&header, 32) };
    if size <= SECTOR || start.checked_add(size).is_none_or(|end| end > part.size()) {
        return Err("bad metadata area size".into());
    }
    let (offset, len, flags) = (le64(&header, 40), le64(&header, 48), le32(&header, 60));
    if (offset == 0 && len == 0) || flags & 1 != 0 {
        return Ok(None);
    }
    if len == 0 || len > MAX_TEXT || len > size || offset >= size {
        return Err("bad metadata location".into());
    }
    let first = size - offset;
    if len <= first {
        return read(part, start + offset, len).map(Some);
    }
    // Wrapped: the rest continues after the header sector.
    let rest = len - first;
    if rest > size - SECTOR {
        return Err("metadata wraps past its own start".into());
    }
    let mut text = read(part, start + offset, first)?;
    text.extend(read(part, start + SECTOR, rest)?);
    Ok(Some(text))
}

// The config tree.

type Section = Vec<(String, Value)>;

#[derive(Debug)]
enum Value {
    Int(u64),
    Str(String),
    List(Vec<Value>),
    Section(Section),
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
    entries: usize,
}

/// Parses the config text; it ends at the first NUL, which LVM writes after it.
fn parse(text: &[u8]) -> Result<Section, String> {
    let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    let mut parser = Parser { text: text.get(..end).unwrap_or(text), pos: 0, entries: 0 };
    parser.body(0)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn fail<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("metadata text: {what} at byte {}", self.pos))
    }

    fn count(&mut self) -> Result<(), String> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return self.fail("too many entries");
        }
        Ok(())
    }

    /// Skips white space and `#` comments.
    fn skip(&mut self) {
        while let Some(b) = self.peek() {
            if b == b'#' {
                while self.peek().is_some_and(|b| b != b'\n') {
                    self.pos += 1;
                }
            } else if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// The entries up to the closing brace (or the end of the text at depth 0).
    fn body(&mut self, depth: usize) -> Result<Section, String> {
        let mut out = Vec::new();
        loop {
            self.skip();
            let key = match self.peek() {
                None if depth == 0 => return Ok(out),
                None => return self.fail("section is not closed"),
                Some(b'}') if depth > 0 => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'"') => self.string()?,
                Some(_) => self.ident()?,
            };
            self.count()?;
            self.skip();
            let value = match self.peek() {
                Some(b'=') => {
                    self.pos += 1;
                    self.skip();
                    self.value()?
                }
                Some(b'{') => {
                    if depth >= MAX_DEPTH {
                        return self.fail("sections nested too deeply");
                    }
                    self.pos += 1;
                    Value::Section(self.body(depth + 1)?)
                }
                _ => return self.fail("expected `=` or `{`"),
            };
            out.push((key, value));
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'"') => self.string().map(Value::Str),
            Some(b'0'..=b'9') => self.int().map(Value::Int),
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip();
                    self.count()?;
                    match self.peek() {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::List(items));
                        }
                        Some(b',') => self.pos += 1,
                        Some(b'"') => items.push(Value::Str(self.string()?)),
                        Some(b'0'..=b'9') => items.push(Value::Int(self.int()?)),
                        _ => return self.fail("unexpected character in a list"),
                    }
                }
            }
            _ => self.fail("expected a value"),
        }
    }

    fn int(&mut self) -> Result<u64, String> {
        let mut n = 0u64;
        while let Some(digit) = self.peek().filter(u8::is_ascii_digit) {
            n = match n.checked_mul(10).and_then(|n| n.checked_add(u64::from(digit - b'0'))) {
                Some(n) => n,
                None => return self.fail("number too large"),
            };
            self.pos += 1;
        }
        Ok(n)
    }

    /// A double-quoted string; `\` makes the next byte literal.
    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut bytes = Vec::new();
        loop {
            match self.peek() {
                None => return self.fail("string is not closed"),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(String::from_utf8_lossy(&bytes).into_owned());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b) => bytes.push(b),
                        None => return self.fail("string is not closed"),
                    }
                }
                Some(b) => bytes.push(b),
            }
            self.pos += 1;
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        let from = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b)) {
            self.pos += 1;
        }
        match self.text.get(from..self.pos) {
            Some(name) if !name.is_empty() => Ok(String::from_utf8_lossy(name).into_owned()),
            _ => self.fail("unexpected character"),
        }
    }
}

fn get<'a>(section: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    section.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn int(section: &[(String, Value)], key: &str) -> Option<u64> {
    match get(section, key)? {
        Value::Int(n) => Some(*n),
        _ => None,
    }
}

fn text<'a>(section: &'a [(String, Value)], key: &str) -> Option<&'a str> {
    match get(section, key)? {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

fn sub<'a>(section: &'a [(String, Value)], key: &str) -> Option<&'a [(String, Value)]> {
    match get(section, key)? {
        Value::Section(s) => Some(s),
        _ => None,
    }
}

/// The volume group of a parsed text: the one top-level section.
fn volume_group_of(top: Section) -> Result<Copy, String> {
    let (name, body) = top
        .into_iter()
        .find_map(|(name, value)| match value {
            Value::Section(body) => Some((name, body)),
            _ => None,
        })
        .ok_or("no volume group in the metadata")?;
    let key = match text(&body, "id") {
        Some(id) if !id.is_empty() => format!("id:{id}"),
        _ => format!("name:{name}"),
    };
    let seqno = int(&body, "seqno").unwrap_or(0);
    Ok(Copy { key, name, seqno, body })
}

/// Characters outside `[A-Za-z0-9_.+-]` become `_`; at most `max` characters are kept.
fn clean(s: &str, max: usize) -> String {
    s.chars().take(max).map(|c| if c.is_ascii_alphanumeric() || "_.+-".contains(c) { c } else { '_' }).collect()
}

/// `name`, or `name_2`, `name_3`... when another volume group's volume already has it.
fn unique(taken: &mut HashSet<String>, name: String) -> String {
    if taken.insert(name.clone()) {
        return name;
    }
    for n in 2.. {
        let suffix = format!("_{n}");
        let candidate = format!("{}{suffix}", clean(&name, MAX_NAME.saturating_sub(suffix.len())));
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
    name
}

/// One piece of a logical volume: `[start, end)` of it is at `offset` of `part`.
struct Segment {
    start: u64,
    end: u64,
    part: Arc<Part>,
    offset: u64,
}

struct Linear {
    segments: Vec<Segment>,
    len: u64,
}

impl ReadAt for Linear {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let eof = || io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the logical volume");
        let end = offset.checked_add(buf.len() as u64).filter(|&end| end <= self.len).ok_or_else(eof)?;
        let (mut pos, mut done) = (offset, 0usize);
        while pos < end {
            let segment = self.segments.get(self.segments.partition_point(|s| s.end <= pos)).ok_or_else(eof)?;
            let n = usize::try_from(end.min(segment.end) - pos).map_err(|_| eof())?;
            let slot = buf.get_mut(done..done.checked_add(n).ok_or_else(eof)?).ok_or_else(eof)?;
            let at = pos.checked_sub(segment.start).and_then(|d| segment.offset.checked_add(d)).ok_or_else(eof)?;
            segment.part.read_at(at, slot)?;
            pos += n as u64;
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// Adds the readable logical volumes of one volume group.
fn volume_group(
    vg: &Copy,
    physical: &HashMap<&str, &Pv>,
    taken: &mut HashSet<String>,
    out: &mut Vec<LogicalVolume>,
    notes: &mut Vec<String>,
) {
    let group = clean(&vg.name, MAX_NAME);
    let extent_bytes = int(&vg.body, "extent_size").filter(|&e| e > 0).and_then(|e| e.checked_mul(SECTOR));
    let Some(extent_bytes) = extent_bytes else {
        notes.push(format!("volume group {group} skipped: no valid extent_size"));
        return;
    };
    // The metadata's name of each physical volume: its uuid and where its extents start.
    let mut pvs: HashMap<&str, (String, u64)> = HashMap::new();
    for (name, value) in sub(&vg.body, "physical_volumes").unwrap_or_default() {
        if let Value::Section(pv) = value {
            let id = text(pv, "id").unwrap_or_default().replace('-', "");
            pvs.insert(name.as_str(), (id, int(pv, "pe_start").unwrap_or(0)));
        }
    }
    let lvs = sub(&vg.body, "logical_volumes").unwrap_or_default();
    if lvs.len() > MAX_LVS {
        notes.push(format!("volume group {group}: only the first {MAX_LVS} logical volumes are read"));
    }
    for (lv_name, value) in lvs.iter().take(MAX_LVS) {
        let Value::Section(lv) = value else { continue };
        let name = unique(taken, clean(&format!("{}-{lv_name}", vg.name), MAX_NAME));
        match linear(lv, extent_bytes, &pvs, physical) {
            Ok(linear) => {
                let len = linear.len;
                out.push(LogicalVolume { name, reader: Arc::new(linear), len });
            }
            Err(why) => notes.push(format!("logical volume {name} skipped: {why}")),
        }
    }
}

/// The segments of one logical volume as a [`Linear`] reader, or why it cannot be read.
fn linear(
    lv: &[(String, Value)],
    extent_bytes: u64,
    pvs: &HashMap<&str, (String, u64)>,
    physical: &HashMap<&str, &Pv>,
) -> Result<Linear, String> {
    let mut segments = Vec::new();
    for (key, value) in lv {
        let (true, Value::Section(seg)) = (key.starts_with("segment"), value) else { continue };
        if segments.len() >= MAX_SEGMENTS {
            return Err(format!("more than {MAX_SEGMENTS} segments"));
        }
        let kind = text(seg, "type").unwrap_or_default();
        if kind != "striped" {
            return Err(format!("segment type \"{}\" is not supported", clean(kind, 40)));
        }
        match int(seg, "stripe_count") {
            Some(1) => {}
            Some(n) => return Err(format!("{n} stripes (striped volumes are not supported)")),
            None => return Err("a segment has no stripe_count".into()),
        }
        let (Some(Value::List(stripes)), Some(first), Some(count)) =
            (get(seg, "stripes"), int(seg, "start_extent"), int(seg, "extent_count"))
        else {
            return Err("a segment is incomplete".into());
        };
        let [Value::Str(pv), Value::Int(pv_extent)] = stripes.as_slice() else {
            return Err("a segment has malformed stripes".into());
        };
        let (id, pe_start) =
            pvs.get(pv.as_str()).ok_or_else(|| format!("physical volume {} is not in the group", clean(pv, 40)))?;
        let part = physical
            .get(id.as_str())
            .map(|pv| &pv.part)
            .ok_or_else(|| format!("physical volume {} is not in the image", clean(pv, 40)))?;
        if count == 0 {
            return Err("a segment is empty".into());
        }
        let place = || {
            let start = first.checked_mul(extent_bytes)?;
            let len = count.checked_mul(extent_bytes)?;
            let offset = pe_start.checked_mul(SECTOR)?.checked_add(pv_extent.checked_mul(extent_bytes)?)?;
            Some((start, start.checked_add(len)?, offset, offset.checked_add(len)?))
        };
        let (start, end, offset, pv_end) = place().ok_or("a segment's numbers overflow")?;
        if pv_end > part.size() {
            return Err("a segment does not fit inside its physical volume".into());
        }
        segments.push(Segment { start, end, part: part.clone(), offset });
    }
    segments.sort_by_key(|s| s.start);
    let mut cursor = 0;
    for segment in &segments {
        if segment.start < cursor {
            return Err("segments overlap".into());
        }
        if segment.start > cursor {
            return Err("there is a gap between segments".into());
        }
        cursor = segment.end;
    }
    if segments.is_empty() {
        return Err("it has no segments".into());
    }
    Ok(Linear { segments, len: cursor })
}

#[cfg(test)]
pub(super) mod testing {
    use super::*;
    use nixcavate_fs::Bytes;

    /// Sectors before the first extent, and sectors per extent.
    pub const PE_START: u64 = 80;
    pub const EXTENT: u64 = 8;
    pub const MDA_START: u64 = 4096;
    pub const MDA_SIZE: u64 = 32768;
    pub const DATA_AT: u64 = PE_START * 512;

    pub struct Mem(pub Vec<u8>);

    impl ReadAt for Mem {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            Bytes(&self.0).read_at(offset, buf)
        }

        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// A 32 character uuid for `n`, and its dashed form as the metadata writes it.
    pub fn uuid(n: char) -> String {
        std::iter::repeat_n(n, 32).collect()
    }

    pub fn dashed(uuid: &str) -> String {
        let cuts = [6, 10, 14, 18, 22, 26];
        let mut out = String::new();
        for (i, c) in uuid.chars().enumerate() {
            if cuts.contains(&i) {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// The byte at `offset` of a physical volume whose extents were filled with `salt`.
    pub fn pattern(offset: u64, salt: u8) -> u8 {
        (offset.wrapping_mul(31) >> 3) as u8 ^ salt
    }

    /// A physical volume: label, header, one metadata area holding `text` at `text_at` of the
    /// circular buffer, and `extents` extents filled with [`pattern`].
    pub fn pv_image(uuid: &str, text: &str, text_at: u64, extents: u64, salt: u8) -> Vec<u8> {
        let mut img = vec![0u8; (DATA_AT + extents * EXTENT * 512) as usize];
        for (i, b) in img.iter_mut().enumerate().skip(DATA_AT as usize) {
            *b = pattern(i as u64, salt);
        }
        let put = |img: &mut Vec<u8>, at: u64, bytes: &[u8]| {
            img[at as usize..at as usize + bytes.len()].copy_from_slice(bytes)
        };
        put(&mut img, 512, b"LABELONE");
        put(&mut img, 512 + 8, &1u64.to_le_bytes());
        put(&mut img, 512 + 20, &32u32.to_le_bytes());
        put(&mut img, 512 + 24, b"LVM2 001");
        let header = 512 + 32;
        put(&mut img, header, uuid.as_bytes());
        let size = img.len() as u64;
        put(&mut img, header + 32, &size.to_le_bytes());
        put(&mut img, header + 40, &DATA_AT.to_le_bytes()); // data area; zero entry follows
        put(&mut img, header + 40 + 32, &MDA_START.to_le_bytes());
        put(&mut img, header + 40 + 40, &MDA_SIZE.to_le_bytes());
        put(&mut img, MDA_START + 4, MDA_MAGIC);
        put(&mut img, MDA_START + 20, &1u32.to_le_bytes());
        put(&mut img, MDA_START + 24, &MDA_START.to_le_bytes());
        put(&mut img, MDA_START + 32, &MDA_SIZE.to_le_bytes());
        let mut body = text.as_bytes().to_vec();
        body.push(0);
        put(&mut img, MDA_START + 40, &text_at.to_le_bytes());
        put(&mut img, MDA_START + 48, &(body.len() as u64).to_le_bytes());
        for (i, b) in body.iter().enumerate() {
            let mut at = text_at + i as u64;
            if at >= MDA_SIZE {
                at = at - MDA_SIZE + SECTOR;
            }
            img[(MDA_START + at) as usize] = *b;
        }
        img
    }

    /// The text of volume group `vg` (a key, quoted if it needs to be) on physical volumes
    /// `pvs` (uuids) with the given logical volume sections.
    pub fn metadata(vg: &str, seqno: u64, pvs: &[String], lvs: &str) -> String {
        let pvs: String = pvs
            .iter()
            .enumerate()
            .map(|(i, u)| {
                format!(
                    "pv{i} {{ id = \"{}\" device = \"/dev/sd{i}\" pe_start = {PE_START} pe_count = 100 }}\n",
                    dashed(u)
                )
            })
            .collect();
        format!(
            "# written by test\ncontents = \"Text Format Volume Group\"\nversion = 1\n{vg} {{\nid = \"vg-id-0\"\nseqno = {seqno}\n\
             extent_size = {EXTENT}\nphysical_volumes {{\n{pvs}}}\nlogical_volumes {{\n{lvs}}}\n}}\ncreation_time = 1\n"
        )
    }

    pub fn lv(name: &str, segments: &str) -> String {
        format!("{name} {{\nstatus = [\"READ\", \"WRITE\", \"VISIBLE\"]\nsegment_count = 1\n{segments}}}\n")
    }

    pub fn segment(n: usize, start: u64, count: u64, pv: usize, pv_extent: u64) -> String {
        format!(
            "segment{n} {{ start_extent = {start} extent_count = {count} type = \"striped\" stripe_count = 1 \
             stripes = [ \"pv{pv}\", {pv_extent} ] }}\n"
        )
    }

    pub fn part(image: Vec<u8>) -> Part {
        let len = image.len() as u64;
        let inner: Shared = Arc::new(Mem(image));
        nixcavate_fs::Slice { inner, start: 0, len }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    const UA: char = 'A';
    const UB: char = 'B';

    fn run(images: Vec<Vec<u8>>) -> (Vec<LogicalVolume>, Vec<String>) {
        open(images.into_iter().enumerate().map(|(i, img)| (i + 1, part(img))).collect())
    }

    fn read_all(lv: &LogicalVolume) -> Vec<u8> {
        let mut buf = vec![0u8; lv.len as usize];
        lv.reader.read_at(0, &mut buf).unwrap();
        buf
    }

    #[test]
    fn one_logical_volume_with_one_segment() {
        let text = metadata("vg0", 3, &[uuid(UA)], &lv("root", &segment(1, 0, 4, 0, 2)));
        let (lvs, notes) = run(vec![pv_image(&uuid(UA), &text, 512, 16, 1)]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(lvs.len(), 1);
        assert_eq!((lvs[0].name.as_str(), lvs[0].len), ("vg0-root", 4 * 4096));
        let expected: Vec<u8> = (0..4 * 4096u64).map(|x| pattern(DATA_AT + 2 * 4096 + x, 1)).collect();
        assert_eq!(read_all(&lvs[0]), expected);
        let mut buf = [0u8; 2];
        assert_eq!(lvs[0].reader.read_at(4 * 4096 - 1, &mut buf).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(lvs[0].reader.read_at(u64::MAX, &mut buf).is_err());
    }

    #[test]
    fn segments_out_of_order_on_two_physical_volumes() {
        // The second extent range is listed first and lives on the other physical volume.
        let segments = format!("{}{}", segment(2, 2, 2, 1, 3), segment(1, 0, 2, 0, 5));
        let text = metadata("vg0", 1, &[uuid(UA), uuid(UB)], &lv("data", &segments));
        let a = pv_image(&uuid(UA), &text, 512, 16, 1);
        let b = pv_image(&uuid(UB), &text, 512, 16, 2);
        let (lvs, notes) = run(vec![a, b]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(lvs.len(), 1, "both copies describe one group");
        let expected = |x: u64| {
            if x < 8192 {
                pattern(DATA_AT + 5 * 4096 + x, 1)
            } else {
                pattern(DATA_AT + 3 * 4096 + (x - 8192), 2)
            }
        };
        assert_eq!(read_all(&lvs[0]), (0..4 * 4096u64).map(expected).collect::<Vec<u8>>());
        let mut across = [0u8; 20];
        lvs[0].reader.read_at(8192 - 10, &mut across).unwrap();
        assert_eq!(across.to_vec(), (8192 - 10..8192 + 10).map(expected).collect::<Vec<u8>>());
    }

    #[test]
    fn metadata_that_wraps_the_circular_buffer() {
        let text = metadata("vg0", 1, &[uuid(UA)], &lv("root", &segment(1, 0, 2, 0, 0)));
        assert!(text.len() > 300);
        let (lvs, notes) = run(vec![pv_image(&uuid(UA), &text, MDA_SIZE - 100, 4, 0)]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(lvs.len(), 1);
    }

    #[test]
    fn the_highest_seqno_wins() {
        let old = metadata("vg0", 1, &[uuid(UA), uuid(UB)], &lv("old", &segment(1, 0, 2, 0, 0)));
        let new = metadata("vg0", 2, &[uuid(UA), uuid(UB)], &lv("new", &segment(1, 0, 2, 1, 0)));
        for swap in [false, true] {
            let mut images = vec![pv_image(&uuid(UA), &old, 512, 4, 1), pv_image(&uuid(UB), &new, 512, 4, 2)];
            if swap {
                images.reverse();
            }
            let (lvs, notes) = run(images);
            assert!(notes.is_empty(), "{notes:?}");
            let names: Vec<&str> = lvs.iter().map(|l| l.name.as_str()).collect();
            assert_eq!(names, ["vg0-new"]);
        }
    }

    #[test]
    fn unsupported_logical_volumes_are_named_once_and_left_out() {
        let cases: Vec<(String, &str)> = vec![
            (
                "segment1 { start_extent = 0 extent_count = 4 type = \"thin\" thin_pool = \"pool\" device_id = 1 }\n"
                    .into(),
                "segment type \"thin\"",
            ),
            (
                "segment1 { start_extent = 0 extent_count = 4 type = \"raid1\" device_count = 2 }\n".into(),
                "segment type \"raid1\"",
            ),
            (
                "segment1 { start_extent = 0 extent_count = 4 type = \"striped\" stripe_count = 2 \
                 stripes = [ \"pv0\", 0, \"pv0\", 4 ] }\n"
                    .into(),
                "2 stripes",
            ),
            (segment(1, 0, 4, 1, 0), "not in the image"),
            (segment(1, 0, 1000, 0, 0), "does not fit"),
            (segment(1, 0, 2, 0, 0) + &segment(2, 3, 1, 0, 4), "gap"),
            (segment(1, 0, 3, 0, 0) + &segment(2, 2, 2, 0, 4), "overlap"),
            (segment(1, 1, 2, 0, 0), "gap"),
            (segment(1, u64::MAX, 2, 0, 0), "overflow"),
        ];
        for (segments, reason) in cases {
            // The second physical volume of the group is not in the image.
            let text = metadata("vg0", 1, &[uuid(UA), uuid(UB)], &lv("x", &segments));
            let (lvs, notes) = run(vec![pv_image(&uuid(UA), &text, 512, 16, 0)]);
            assert!(lvs.is_empty(), "{reason}");
            assert_eq!(notes.len(), 1, "{reason}: {notes:?}");
            assert!(notes[0].contains("vg0-x") && notes[0].contains(reason), "{reason}: {notes:?}");
        }
    }

    #[test]
    fn names_are_made_safe_and_unique() {
        assert_eq!(clean("a b/é.+-_9", 128), "a_b__.+-_9");
        assert_eq!(clean(&"x".repeat(300), MAX_NAME).len(), MAX_NAME);
        let lvs = lv("\"a/b\\\"c\"", &segment(1, 0, 1, 0, 0)) + &lv("\"a_b_c\"", &segment(1, 0, 1, 0, 1));
        let text = metadata("\"my vg\"", 1, &[uuid(UA)], &lvs);
        let (lvs, notes) = run(vec![pv_image(&uuid(UA), &text, 512, 4, 0)]);
        assert!(notes.is_empty(), "{notes:?}");
        let names: Vec<&str> = lvs.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["my_vg-a_b_c", "my_vg-a_b_c_2"]);
    }

    #[test]
    fn an_unreadable_physical_volume_gives_one_note() {
        let (lvs, notes) = run(vec![vec![0u8; 4096]]);
        assert!(lvs.is_empty());
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("partition 1"), "{notes:?}");
        // A good label with no metadata area contents.
        let mut img = pv_image(&uuid(UA), "", 512, 1, 0);
        img[(MDA_START + 4) as usize] ^= 1;
        let (lvs, notes) = run(vec![img]);
        assert!(lvs.is_empty());
        assert_eq!(notes.len(), 1, "{notes:?}");
    }

    #[test]
    fn the_config_text_parser() {
        let tree =
            parse(b"# c\na = 1 b = \"x\\\"y\\\\\" l = [ 1, \"s\" ] s { c = 18446744073709551615 }\0junk {").unwrap();
        assert_eq!(tree.len(), 4);
        assert_eq!(text(&tree, "b"), Some("x\"y\\"));
        assert_eq!(int(sub(&tree, "s").unwrap(), "c"), Some(u64::MAX));
        assert!(parse(b"a = 18446744073709551616").is_err());
        assert!(parse(b"a = -1").is_err());
        assert!(parse(b"a { b = 1").is_err());
        assert!(parse(b"}").is_err());
        assert!(parse(b"a = \"open").is_err());
        let nested = |n: usize| "a { ".repeat(n) + &"} ".repeat(n);
        assert!(parse(nested(MAX_DEPTH).as_bytes()).is_ok());
        assert!(parse(nested(MAX_DEPTH + 1).as_bytes()).is_err());
        let many = "a = 1 ".repeat(MAX_ENTRIES + 1);
        assert!(parse(many.as_bytes()).is_err());
    }

    /// A small deterministic generator, so a failure repeats.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn base() -> (Vec<u8>, usize) {
        let segments = segment(1, 0, 2, 0, 0) + &segment(2, 2, 2, 0, 4);
        let text = metadata("vg0", 1, &[uuid(UA)], &lv("root", &segments));
        (pv_image(&uuid(UA), &text, 512, 8, 3), text.len())
    }

    /// Opens `img` and reads a little of every logical volume found.
    fn exercise(img: Vec<u8>) {
        let (lvs, _) = open(vec![(1, part(img))]);
        for lv in lvs {
            let mut buf = vec![0u8; 8192];
            let _ = lv.reader.read_at(0, &mut buf);
            let _ = lv.reader.read_at(lv.len.saturating_sub(1), &mut buf[..1]);
        }
    }

    #[test]
    fn flipped_bytes_never_panic() {
        let (base, text_len) = base();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let regions =
            [(512u64, 1024u64), (MDA_START, MDA_START + 512), (MDA_START + 512, MDA_START + 512 + text_len as u64)];
        for round in 0..6000 {
            let mut img = base.clone();
            let (from, to) = regions[round % 3];
            for _ in 0..=rng.next() % 3 {
                let at = (from + rng.next() % (to - from)) as usize;
                img[at] = match rng.next() % 3 {
                    0 => img[at] ^ (1 << (rng.next() % 8)),
                    1 => b"{}[]\"=\\#0 9"[(rng.next() % 11) as usize],
                    _ => rng.next() as u8,
                };
            }
            exercise(img);
        }
    }

    #[test]
    fn truncated_images_never_panic() {
        let (base, _) = base();
        for len in (0..base.len())
            .step_by(61)
            .chain([0, 1, 31, 511, 512, 543, 544, 575, 576, 4096, 4135, 5000, 36_864, 40_959])
        {
            let mut img = base.clone();
            img.truncate(len);
            let (lvs, notes) = open(vec![(1, part(img))]);
            // The last extent read ends at 57344: anything shorter cannot hold the volume.
            if len < 57_344 {
                assert!(lvs.is_empty(), "{len}");
                assert!(!notes.is_empty(), "{len}");
            }
        }
    }
}

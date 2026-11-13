//! Bookmark data (`book` blobs, as stored in shared file lists, Dock and login item files):
//! a header, a data area of typed items and one or more tables of contents mapping numeric keys
//! to items. All integers are little-endian except dates (big-endian double, seconds since
//! 2001-01-01).
//!
//! The format is not published by Apple; the layout and key numbers follow the open-source
//! `mac_alias` project's reverse-engineered description (read for layout only, nothing copied),
//! and were checked against bookmark data made by Foundation itself for a file the checker
//! created (see docs/LIMITATIONS.md). Only the fields that say what the bookmark pointed at
//! are decoded. Security extension tokens and icon data are never read.

use super::util::clip;
use nixcavate_core::Timestamp;
use std::collections::HashMap;

const TOC_MAGIC: u32 = 0xffff_fffe;
const MAX_TOCS: usize = 8;
const MAX_ENTRIES: u32 = 256;
const MAX_ITEMS: usize = 4096;
const MAX_DEPTH: usize = 4;

const KEY_PATH: u32 = 0x1004;
const KEY_FILE_ID: u32 = 0x1030;
const KEY_FILE_CREATED: u32 = 0x1040;
const KEY_VOLUME_PATH: u32 = 0x2002;
const KEY_VOLUME_NAME: u32 = 0x2010;
const KEY_VOLUME_UUID: u32 = 0x2011;
const KEY_VOLUME_SIZE: u32 = 0x2012;
const KEY_VOLUME_CREATED: u32 = 0x2013;
const KEY_USER_NAME: u32 = 0xc011;
const KEY_UID: u32 = 0xc012;

#[derive(Debug, Clone, PartialEq)]
enum Item {
    Text(String),
    Number(i64),
    Date(f64),
    List(Vec<Item>),
    Other,
}

/// What a bookmark says about its target.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bookmark {
    /// The path of the target on its volume, components joined with `/`, without the volume path.
    pub path: Option<String>,
    pub volume_path: Option<String>,
    pub volume_name: Option<String>,
    pub volume_uuid: Option<String>,
    pub volume_size: Option<i64>,
    pub volume_created: Option<Timestamp>,
    pub file_created: Option<Timestamp>,
    pub file_id: Option<i64>,
    /// The user and uid that made the bookmark.
    pub user_name: Option<String>,
    pub uid: Option<i64>,
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

struct Reader<'a> {
    data: &'a [u8],
    header: usize,
    items: usize,
}

impl Reader<'_> {
    fn item(&mut self, offset: u32, depth: usize) -> Option<Item> {
        self.items += 1;
        if self.items > MAX_ITEMS || depth > MAX_DEPTH {
            return None;
        }
        let at = self.header.checked_add(usize::try_from(offset).ok()?)?;
        let length = usize::try_from(u32_at(self.data, at)?).ok()?;
        let code = u32_at(self.data, at.checked_add(4)?)?;
        let body = self.data.get(at.checked_add(8)?..at.checked_add(8)?.checked_add(length)?)?;
        let (kind, sub) = (code & 0xffff_ff00, code & 0xff);
        Some(match kind {
            0x0100 => Item::Text(clip(&String::from_utf8_lossy(body), 1024)),
            0x0300 => match (sub, body.len()) {
                (1, 1) => Item::Number(i64::from(body[0] as i8)),
                (2, 2) => Item::Number(i64::from(i16::from_le_bytes(body.try_into().ok()?))),
                (3, 4) => Item::Number(i64::from(i32::from_le_bytes(body.try_into().ok()?))),
                (4, 8) => Item::Number(i64::from_le_bytes(body.try_into().ok()?)),
                _ => Item::Other,
            },
            0x0400 => Item::Date(f64::from_be_bytes(body.try_into().ok()?)),
            0x0600 => {
                let mut list = Vec::new();
                for chunk in body.chunks_exact(4).take(MAX_ITEMS) {
                    let offset = u32::from_le_bytes(chunk.try_into().ok()?);
                    list.push(self.item(offset, depth + 1)?);
                }
                Item::List(list)
            }
            _ => Item::Other,
        })
    }
}

fn text(item: Option<&Item>) -> Option<String> {
    match item? {
        Item::Text(t) => Some(t.clone()),
        _ => None,
    }
}

fn number(item: Option<&Item>) -> Option<i64> {
    match item? {
        Item::Number(n) => Some(*n),
        _ => None,
    }
}

fn date(item: Option<&Item>) -> Option<Timestamp> {
    match item? {
        Item::Date(secs) => super::plist_util::mac_time(*secs),
        _ => None,
    }
}

/// Decodes bookmark data; `None` when it is not a bookmark or is too damaged to read.
pub fn decode(data: &[u8]) -> Option<Bookmark> {
    if data.get(..4)? != b"book" {
        return None;
    }
    let size = usize::try_from(u32_at(data, 4)?).ok()?;
    let header = usize::try_from(u32_at(data, 12)?).ok()?;
    if header < 16 || header > size || size > data.len() {
        return None;
    }
    let mut toc_offset = usize::try_from(u32_at(data, header)?).ok()?;
    let mut keys: HashMap<u32, u32> = HashMap::new();
    for _ in 0..MAX_TOCS {
        if toc_offset == 0 {
            break;
        }
        let base = header.checked_add(toc_offset)?;
        if u32_at(data, base.checked_add(4)?)? != TOC_MAGIC {
            break;
        }
        let next = usize::try_from(u32_at(data, base.checked_add(12)?)?).ok()?;
        let count = u32_at(data, base.checked_add(16)?)?.min(MAX_ENTRIES);
        for n in 0..count as usize {
            let entry = base.checked_add(20)?.checked_add(n.checked_mul(12)?)?;
            let (key, value) = (u32_at(data, entry)?, u32_at(data, entry.checked_add(4)?)?);
            keys.entry(key).or_insert(value);
        }
        toc_offset = next;
    }
    let mut reader = Reader { data: &data[..size], header, items: 0 };
    let mut get = |key: u32| keys.get(&key).and_then(|&offset| reader.item(offset, 0));
    let path = match get(KEY_PATH) {
        Some(Item::List(parts)) => {
            let parts: Vec<String> = parts.iter().filter_map(|p| text(Some(p))).collect();
            Some(parts.join("/"))
        }
        _ => None,
    };
    Some(Bookmark {
        path,
        volume_path: text(get(KEY_VOLUME_PATH).as_ref()),
        volume_name: text(get(KEY_VOLUME_NAME).as_ref()),
        volume_uuid: text(get(KEY_VOLUME_UUID).as_ref()),
        volume_size: number(get(KEY_VOLUME_SIZE).as_ref()),
        volume_created: date(get(KEY_VOLUME_CREATED).as_ref()),
        file_created: date(get(KEY_FILE_CREATED).as_ref()),
        file_id: number(get(KEY_FILE_ID).as_ref()),
        user_name: text(get(KEY_USER_NAME).as_ref()),
        uid: number(get(KEY_UID).as_ref()),
    })
}

impl Bookmark {
    /// The target's full path: the volume path (when it is not the root) and the components.
    pub fn full_path(&self) -> Option<String> {
        let path = self.path.as_deref()?;
        let volume = self.volume_path.as_deref().unwrap_or("/").trim_end_matches('/');
        Some(format!("{volume}/{path}"))
    }
}

/// A bookmark built from typed items, for tests: `(key, item bytes)` with items already encoded.
#[cfg(test)]
pub fn build(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let header = 48usize;
    let mut area = vec![0u8; 4]; // first TOC offset, patched below
    let mut offsets = Vec::new();
    for (_, item) in entries {
        offsets.push(area.len() as u32);
        area.extend(item);
        while area.len() % 4 != 0 {
            area.push(0);
        }
    }
    let toc = area.len() as u32;
    area[0..4].copy_from_slice(&toc.to_le_bytes());
    area.extend(((12 * entries.len() as u32) + 12).to_le_bytes());
    area.extend(TOC_MAGIC.to_le_bytes());
    area.extend(1u32.to_le_bytes());
    area.extend(0u32.to_le_bytes());
    area.extend((entries.len() as u32).to_le_bytes());
    for ((key, _), offset) in entries.iter().zip(offsets) {
        area.extend(key.to_le_bytes());
        area.extend(offset.to_le_bytes());
        area.extend(0u32.to_le_bytes());
    }
    let mut out = b"book".to_vec();
    out.extend(((header + area.len()) as u32).to_le_bytes());
    out.extend(0x1004_0000u32.to_le_bytes());
    out.extend((header as u32).to_le_bytes());
    out.resize(header, 0);
    out.extend(area);
    out
}

#[cfg(test)]
pub mod encode {
    pub fn text(s: &str) -> Vec<u8> {
        let mut out = (s.len() as u32).to_le_bytes().to_vec();
        out.extend(0x0101u32.to_le_bytes());
        out.extend(s.as_bytes());
        out
    }

    pub fn number(n: i64) -> Vec<u8> {
        let mut out = 8u32.to_le_bytes().to_vec();
        out.extend(0x0304u32.to_le_bytes());
        out.extend(n.to_le_bytes());
        out
    }

    pub fn date(secs: f64) -> Vec<u8> {
        let mut out = 8u32.to_le_bytes().to_vec();
        out.extend(0x0400u32.to_le_bytes());
        out.extend(secs.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::encode as e;
    use super::*;

    /// An array item whose elements are at `offsets` (data-area offsets of other items). The
    /// helper places the elements first, so the array refers back to them.
    fn sample() -> Vec<u8> {
        // Elements: "Users", "alice", "notes.txt" strings are built as separate entries with
        // unused keys, then the array points to them.
        let strings = ["Users", "alice", "notes.txt"];
        let mut entries: Vec<(u32, Vec<u8>)> =
            strings.iter().enumerate().map(|(i, s)| (0x9000 + i as u32, e::text(s))).collect();
        // Offsets of the strings in the data area: 4 (toc pointer) then each padded to 4.
        let mut offsets = Vec::new();
        let mut at = 4u32;
        for (_, item) in &entries {
            offsets.push(at);
            at += (item.len() as u32).div_ceil(4) * 4;
        }
        let mut array = ((offsets.len() * 4) as u32).to_le_bytes().to_vec();
        array.extend(0x0601u32.to_le_bytes());
        for o in offsets {
            array.extend(o.to_le_bytes());
        }
        entries.push((KEY_PATH, array));
        entries.push((KEY_VOLUME_NAME, e::text("Macintosh HD")));
        entries.push((KEY_VOLUME_PATH, e::text("/")));
        entries.push((KEY_FILE_ID, e::number(123_456)));
        entries.push((KEY_FILE_CREATED, e::date(700_000_000.0)));
        entries.push((KEY_USER_NAME, e::text("alice")));
        entries.push((KEY_UID, e::number(501)));
        build(&entries)
    }

    #[test]
    fn decodes_the_target_of_a_bookmark() {
        let b = decode(&sample()).unwrap();
        assert_eq!(b.path.as_deref(), Some("Users/alice/notes.txt"));
        assert_eq!(b.full_path().as_deref(), Some("/Users/alice/notes.txt"));
        assert_eq!(b.volume_name.as_deref(), Some("Macintosh HD"));
        assert_eq!(b.file_id, Some(123_456));
        assert_eq!(b.uid, Some(501));
        assert_eq!(b.file_created.unwrap().to_rfc3339(), "2023-03-08T20:26:40Z");
    }

    #[test]
    fn not_a_bookmark() {
        assert!(decode(b"").is_none());
        assert!(decode(b"book").is_none());
        assert!(decode(b"alis0000000000000000").is_none());
    }

    #[test]
    fn damaged_bookmarks_never_panic() {
        let data = sample();
        for len in 0..data.len() {
            let _ = decode(&data[..len]);
        }
        let mut state = 0x1234_5678_9abc_def0_u64;
        for _ in 0..20_000 {
            let mut copy = data.clone();
            for _ in 0..4 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state % copy.len() as u64) as usize;
                copy[at] ^= (state >> 32) as u8 | 1;
            }
            let _ = decode(&copy);
        }
    }

    #[test]
    fn an_array_that_contains_itself_terminates() {
        let mut entries = vec![(KEY_PATH, Vec::new())];
        // One array element pointing at the array itself (offset 4).
        let mut array = 4u32.to_le_bytes().to_vec();
        array.extend(0x0601u32.to_le_bytes());
        array.extend(4u32.to_le_bytes());
        entries[0].1 = array;
        let _ = decode(&build(&entries));
    }

    /// Prints the decoding of a bookmark made by Foundation for a file the checker created:
    /// `NIXCAVATE_BOOKMARK=<file> cargo test -p nixcavate-artifacts --lib real_bookmark -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs a bookmark file; see docs/LIMITATIONS.md"]
    fn real_bookmark() {
        let path = std::env::var("NIXCAVATE_BOOKMARK").unwrap();
        let data = std::fs::read(path).unwrap();
        println!("{:#?}", decode(&data));
    }
}

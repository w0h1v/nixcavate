//! A read-only reader for BoltDB / bbolt files, the key-value store containerd keeps its
//! metadata in (`io.containerd.metadata.v1.bolt/meta.db`). Written from the format's public
//! description (the bbolt source's `page.go`, `db.go`, `bucket.go` and `freelist`-independent
//! layout notes); only reading is implemented, and it never follows the freelist.
//!
//! Layout, all little-endian: the file is an array of pages of `page_size` bytes. Pages 0 and 1
//! are meta pages; the one with the higher transaction id and a valid checksum is current.
//! Every page starts with a 16-byte header: `id u64`, `flags u16`, `count u16`, `overflow u32`
//! (a page with `overflow` n spans n+1 consecutive pages). A meta page holds, after the
//! header: `magic u32` (0xED0CDAED), `version u32` (2), `page_size u32`, `flags u32`, the root
//! bucket (`root u64`, `sequence u64`), `freelist u64`, `high-water pgid u64`, `txid u64` and a
//! `checksum u64`, FNV-1a 64 of the preceding 56 bytes.
//!
//! A branch page (flag 0x01) has `count` 16-byte elements `pos u32, key_size u32, pgid u64`;
//! a leaf page (flag 0x02) has `count` elements `flags u32, pos u32, key_size u32, value_size u32`.
//! `pos` is relative to the start of the element; the key is there, and a leaf's value follows
//! the key. A leaf element with flag 0x01 is a nested bucket: its value is a 16-byte header
//! (`root u64`, `sequence u64`) and, when `root` is 0, an inline page that follows the header.
//!
//! Every offset, length and page number comes from the file and is checked against the bytes
//! present; traversals are bounded by depth and by a visit budget proportional to the file, so
//! a cyclic or forged tree ends with an error instead of looping.

use nixcavate_core::{Error, Result};

const MAGIC: u32 = 0xED0C_DAED;
const VERSION: u32 = 2;
const PAGE_HEADER: usize = 16;
const BRANCH: u16 = 0x01;
const LEAF: u16 = 0x02;
const BUCKET_LEAF: u32 = 0x01;
/// The deepest tree walked. A real tree of any size is a handful of levels deep.
const MAX_DEPTH: usize = 32;

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// An open database: the file's bytes and the current root bucket.
pub struct Bolt<'a> {
    data: &'a [u8],
    page_size: usize,
    root: u64,
}

/// A value in a bucket.
pub enum Value<'a> {
    Data(&'a [u8]),
    Bucket(Bucket<'a>),
}

/// A bucket: a page tree, or a page held inside its parent's value.
#[derive(Clone, Copy)]
pub struct Bucket<'a> {
    db: &'a Bolt<'a>,
    /// The root page, or 0 for an inline bucket held in `inline`.
    root: u64,
    inline: &'a [u8],
}

impl<'a> Bolt<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let page_size = u32_at(data, PAGE_HEADER + 8)
            .map(|p| p as usize)
            .filter(|p| p.is_power_of_two() && (512..=(1 << 20)).contains(p))
            .ok_or_else(|| Error::format("not a BoltDB file (no valid page size in the first meta page)"))?;
        let mut best: Option<(u64, u64)> = None;
        for index in 0..2usize {
            let at = index.checked_mul(page_size).ok_or_else(|| Error::format("bad page size"))?;
            let meta = at.checked_add(PAGE_HEADER).and_then(|m| data.get(m..m.checked_add(64)?));
            let Some(meta) = meta else { continue };
            let valid = u32_at(meta, 0) == Some(MAGIC)
                && u32_at(meta, 4) == Some(VERSION)
                && u32_at(meta, 8).map(|p| p as usize) == Some(page_size)
                && u64_at(meta, 56) == Some(fnv1a64(&meta[..56]));
            let (Some(root), Some(txid)) = (u64_at(meta, 16), u64_at(meta, 48)) else { continue };
            if valid && best.is_none_or(|(_, t)| txid > t) {
                best = Some((root, txid));
            }
        }
        let (root, _) = best.ok_or_else(|| Error::format("not a BoltDB file (no valid meta page)"))?;
        Ok(Self { data, page_size, root })
    }

    pub fn root(&'a self) -> Bucket<'a> {
        Bucket { db: self, root: self.root, inline: &[] }
    }

    /// The bytes of page `id` and its overflow pages.
    fn page(&self, id: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(id).ok()?.checked_mul(self.page_size)?;
        let header = self.data.get(start..start.checked_add(PAGE_HEADER)?)?;
        let overflow = u32_at(header, 12)? as usize;
        let end = start.checked_add(overflow.checked_add(1)?.checked_mul(self.page_size)?)?;
        // A file cut short (an image of a volume in use) keeps whole pages only: a page that
        // runs past the end is not trusted.
        self.data.get(start..end)
    }
}

/// The elements of a leaf or branch page held in `page`.
struct Elements<'a> {
    page: &'a [u8],
    flags: u16,
    count: usize,
}

impl<'a> Elements<'a> {
    fn new(page: &'a [u8]) -> Option<Self> {
        let flags = u16_at(page, 8)?;
        let count = u16_at(page, 10)? as usize;
        // 16 bytes per element must fit in the page.
        let table = count.checked_mul(16)?.checked_add(PAGE_HEADER)?;
        (page.len() >= table && matches!(flags, BRANCH | LEAF)).then_some(Self { page, flags, count })
    }

    fn element(&self, index: usize) -> Option<usize> {
        (index < self.count).then(|| PAGE_HEADER + index * 16)
    }

    /// A slice of the page at `element + pos`.
    fn slice(&self, element: usize, pos: u32, len: u32) -> Option<&'a [u8]> {
        let start = element.checked_add(pos as usize)?;
        self.page.get(start..start.checked_add(len as usize)?)
    }
}

impl<'a> Bucket<'a> {
    fn root_page(&self) -> Option<&'a [u8]> {
        if self.root == 0 {
            Some(self.inline)
        } else {
            self.db.page(self.root)
        }
    }

    /// Calls `f` with every key and value, in key order. A damaged tree is an error after
    /// whatever was readable before it has been delivered.
    pub fn for_each(&self, mut f: impl FnMut(&'a [u8], Value<'a>)) -> Result<()> {
        let mut budget = self.db.data.len() / self.db.page_size + 1;
        let page = self.root_page().ok_or_else(|| Error::format("a bucket's root page is outside the file"))?;
        self.walk(page, 0, &mut budget, &mut f)
    }

    fn walk(
        &self,
        page: &'a [u8],
        depth: usize,
        budget: &mut usize,
        f: &mut impl FnMut(&'a [u8], Value<'a>),
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::format("the BoltDB page tree is too deep"));
        }
        // Each page is visited at most once in a sound tree, so a visit count above the file's
        // page count means a cycle.
        *budget = budget.checked_sub(1).ok_or_else(|| Error::format("the BoltDB page tree loops"))?;
        let elements = Elements::new(page).ok_or_else(|| Error::format("a BoltDB page has an invalid header"))?;
        for index in 0..elements.count {
            let bad = || Error::format("a BoltDB element points outside its page");
            let at = elements.element(index).ok_or_else(bad)?;
            if elements.flags == BRANCH {
                let (pos, key_size, child) = (u32_at(page, at), u32_at(page, at + 4), u64_at(page, at + 8));
                let (Some(_), Some(_), Some(child)) = (pos, key_size, child) else { return Err(bad()) };
                let child = self.db.page(child).ok_or_else(bad)?;
                self.walk(child, depth + 1, budget, f)?;
            } else {
                let (flags, pos, key_size, value_size) =
                    (u32_at(page, at), u32_at(page, at + 4), u32_at(page, at + 8), u32_at(page, at + 12));
                let (Some(flags), Some(pos), Some(key_size), Some(value_size)) = (flags, pos, key_size, value_size)
                else {
                    return Err(bad());
                };
                let key = elements.slice(at, pos, key_size).ok_or_else(bad)?;
                let value_pos = pos.checked_add(key_size).ok_or_else(bad)?;
                let value = elements.slice(at, value_pos, value_size).ok_or_else(bad)?;
                if flags & BUCKET_LEAF == 0 {
                    f(key, Value::Data(value));
                } else {
                    let root = u64_at(value, 0).ok_or_else(bad)?;
                    let inline = if root == 0 { value.get(16..).ok_or_else(bad)? } else { &[] };
                    f(key, Value::Bucket(Bucket { db: self.db, root, inline }));
                }
            }
        }
        Ok(())
    }

    /// The nested bucket called `name`, if there is one.
    pub fn bucket(&self, name: &[u8]) -> Option<Bucket<'a>> {
        let mut found = None;
        let _ = self.for_each(|key, value| {
            if let (true, Value::Bucket(bucket)) = (key == name && found.is_none(), value) {
                found = Some(bucket);
            }
        });
        found
    }

    /// The plain value stored under `key`, if there is one.
    pub fn get(&self, key: &[u8]) -> Option<&'a [u8]> {
        let mut found = None;
        let _ = self.for_each(|k, value| {
            if let (true, Value::Data(data)) = (k == key && found.is_none(), value) {
                found = Some(data);
            }
        });
        found
    }
}

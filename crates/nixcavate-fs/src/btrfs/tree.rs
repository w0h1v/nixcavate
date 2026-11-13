//! Keys, the chunk map (logical to physical addresses) and B-tree nodes ("On-disk Format" on
//! the Btrfs wiki: "Header", "Key", "Chunk items", and `struct btrfs_header`,
//! `struct btrfs_item`, `struct btrfs_key_ptr` in the kernel's `btrfs_tree.h`).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::{le16, le32, le64, Error, ReadAt, Result};

/// `struct btrfs_header`; items or key pointers follow it.
pub(crate) const HEADER: usize = 101;
/// `struct btrfs_item`: key, data offset, data size.
const ITEM: usize = 25;
/// `struct btrfs_key_ptr`: key, child address, generation.
const KEY_PTR: usize = 33;
/// Levels run from 0 (leaves) to 7: `BTRFS_MAX_LEVEL` is 8.
pub(crate) const MAX_LEVEL: u8 = 7;

/// Bytes of decoded nodes one operation keeps before its cache is dropped and refilled.
const CACHE_BYTES: usize = 64 << 20;
/// Node fetches (cache hits included) one operation may make: per node a walk reports, one
/// inode lookup and its share of directory scans fit many times over.
const FETCH_BUDGET: u64 = crate::MAX_NODES * 64;
/// Chunks accepted: one per GiB of a 256 TiB filesystem.
pub(crate) const MAX_CHUNKS: usize = 1 << 18;
/// Stripes accepted in one chunk.
const MAX_STRIPES: usize = 256;

pub(crate) const CHUNK_ITEM: u8 = 228;

/// Block group profile bits of a chunk's type (`BTRFS_BLOCK_GROUP_*`).
const RAID0: u64 = 1 << 3;
const RAID1: u64 = 1 << 4;
const DUP: u64 = 1 << 5;
const RAID10: u64 = 1 << 6;
const RAID5: u64 = 1 << 7;
const RAID6: u64 = 1 << 8;
const RAID1C3: u64 = 1 << 9;
const RAID1C4: u64 = 1 << 10;
const PROFILES: u64 = RAID0 | RAID1 | DUP | RAID10 | RAID5 | RAID6 | RAID1C3 | RAID1C4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Key {
    pub obj: u64,
    pub ty: u8,
    pub off: u64,
}

impl Key {
    pub fn new(obj: u64, ty: u8, off: u64) -> Key {
        Key { obj, ty, off }
    }

    /// `struct btrfs_disk_key` at `at`.
    pub fn parse(b: &[u8], at: usize) -> Key {
        Key { obj: le64(b, at), ty: b.get(at.wrapping_add(8)).copied().unwrap_or(0), off: le64(b, at.wrapping_add(9)) }
    }
}

/// The name of a profile, for messages.
pub(crate) fn profile_name(kind: u64) -> &'static str {
    match kind & PROFILES {
        0 => "single",
        RAID0 => "RAID0",
        RAID1 => "RAID1",
        DUP => "DUP",
        RAID10 => "RAID10",
        RAID5 => "RAID5",
        RAID6 => "RAID6",
        RAID1C3 => "RAID1C3",
        RAID1C4 => "RAID1C4",
        _ => "mixed-profile",
    }
}

/// One chunk: `length` bytes of logical address space from `logical`, stored on the stripes.
#[derive(Debug)]
struct Chunk {
    logical: u64,
    length: u64,
    kind: u64,
    /// (device id, physical offset) of each stripe.
    stripes: Vec<(u64, u64)>,
}

/// The logical-to-physical map of the device in the image.
pub(crate) struct Chunks {
    list: Vec<Chunk>,
    /// This device's id (the superblock's `dev_item.devid`) and size.
    devid: u64,
    dev_size: u64,
}

impl Chunks {
    pub fn new(devid: u64, dev_size: u64) -> Chunks {
        Chunks { list: Vec::new(), devid, dev_size }
    }

    /// Adds the `struct btrfs_chunk` at the start of `b` (from the superblock's array or the
    /// chunk tree) for `logical`; returns its size in bytes. A chunk that repeats one already
    /// known replaces it; one that overlaps another is damage.
    pub fn add(&mut self, logical: u64, b: &[u8]) -> Result<usize> {
        let length = le64(b, 0);
        let kind = le64(b, 24);
        let count = usize::from(le16(b, 44));
        let size = 48 + 32 * count;
        if count == 0 || count > MAX_STRIPES || b.len() < size {
            return Err(Error::corrupt(format!("chunk at {logical:#x}: {count} stripes")));
        }
        let end = logical.checked_add(length).filter(|_| length > 0);
        let Some(end) = end else { return Err(Error::corrupt(format!("chunk at {logical:#x}: length {length}"))) };
        let stripes = (0..count).map(|i| (le64(b, 48 + 32 * i), le64(b, 56 + 32 * i))).collect();
        let chunk = Chunk { logical, length, kind, stripes };
        let at = self.list.partition_point(|c| c.logical < logical);
        if self.list.get(at).is_some_and(|c| c.logical == logical) {
            self.list[at] = chunk;
        } else {
            let overlaps =
                at.checked_sub(1).and_then(|p| self.list.get(p)).is_some_and(|p| p.logical + p.length > logical)
                    || self.list.get(at).is_some_and(|n| n.logical < end);
            if overlaps {
                return Err(Error::corrupt(format!("chunk at {logical:#x} overlaps another")));
            }
            if self.list.len() >= MAX_CHUNKS {
                return Err(Error::corrupt("too many chunks"));
            }
            self.list.insert(at, chunk);
        }
        Ok(size)
    }

    /// The physical address of `len` bytes at `logical`, and how many of them lie in the same
    /// chunk (at most `len`).
    fn map(&self, logical: u64, len: u64) -> Result<(u64, u64)> {
        let at = self.list.partition_point(|c| c.logical <= logical);
        let chunk = at.checked_sub(1).and_then(|i| self.list.get(i)).filter(|c| logical - c.logical < c.length);
        let Some(c) = chunk else {
            return Err(Error::corrupt(format!("logical address {logical:#x} is in no chunk")));
        };
        let within = logical - c.logical;
        let run = len.min(c.length - within);
        if c.kind & (RAID0 | RAID10 | RAID5 | RAID6) != 0 {
            return Err(Error::unsupported(format!("data in a {} block group", profile_name(c.kind))));
        }
        // Single, DUP and the RAID1 family keep a whole copy on each stripe: read ours.
        let mut ours = false;
        for &(devid, offset) in &c.stripes {
            if devid != self.devid {
                continue;
            }
            ours = true;
            let phys = offset.checked_add(within);
            if let Some(p) = phys.filter(|p| p.checked_add(run).is_some_and(|e| e <= self.dev_size)) {
                return Ok((p, run));
            }
        }
        if ours {
            Err(Error::corrupt(format!("chunk at {:#x} maps past the end of the device", c.logical)))
        } else {
            Err(Error::unsupported(format!(
                "data in a {} block group with no copy on this device (a multi-device filesystem)",
                profile_name(c.kind)
            )))
        }
    }

    /// Fills `buf` from logical address `logical`, across chunks if needed.
    pub fn read(&self, img: &dyn ReadAt, logical: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = logical
                .checked_add(done as u64)
                .ok_or_else(|| Error::corrupt(format!("logical address {logical:#x} overflows")))?;
            let (phys, run) = self.map(at, (buf.len() - done) as u64)?;
            let run = run as usize;
            img.read_at(phys, &mut buf[done..done + run])?;
            done += run;
        }
        Ok(())
    }

    /// The profiles of block groups this reader cannot read, for one warning.
    pub fn unreadable_profiles(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for c in &self.list {
            let name = profile_name(c.kind);
            let striped = c.kind & (RAID0 | RAID10 | RAID5 | RAID6) != 0;
            let elsewhere = !c.stripes.iter().any(|s| s.0 == self.devid);
            let label = if striped {
                name
            } else if elsewhere {
                "on another device"
            } else {
                continue;
            };
            if !out.contains(&label) {
                out.push(label);
            }
        }
        out
    }

    /// Adds every chunk listed in the superblock's `sys_chunk_array`.
    pub fn add_array(&mut self, array: &[u8]) -> Result<()> {
        let mut at = 0usize;
        while at < array.len() {
            let key = Key::parse(array, at);
            if key.ty != CHUNK_ITEM || array.len() < at + 17 {
                return Err(Error::corrupt("system chunk array holds a key that is not a chunk"));
            }
            at += 17;
            at += self.add(key.off, &array[at..])?;
        }
        Ok(())
    }
}

/// A decoded tree block.
pub(crate) struct Node {
    data: Vec<u8>,
    pub level: u8,
    pub nritems: usize,
}

impl Node {
    /// Checks the header: its address, the filesystem id, the level, the owner when one is
    /// expected, and that the items or key pointers fit the block.
    fn parse(data: Vec<u8>, bytenr: u64, fsid: &[u8; 16], owner: Option<u64>) -> Result<Node> {
        let bad = |what: &str| Error::corrupt(format!("tree block {bytenr:#x}: {what}"));
        if le64(&data, 0x30) != bytenr {
            return Err(bad("records another address"));
        }
        if data.get(0x20..0x30) != Some(fsid.as_slice()) {
            return Err(bad("belongs to another filesystem"));
        }
        if owner.is_some_and(|o| le64(&data, 0x58) != o) {
            return Err(bad("belongs to another tree"));
        }
        let level = data.get(0x64).copied().unwrap_or(u8::MAX);
        if level > MAX_LEVEL {
            return Err(bad("level out of range"));
        }
        let nritems = le32(&data, 0x60) as usize;
        let entry = if level == 0 { ITEM } else { KEY_PTR };
        if nritems > (data.len() - HEADER) / entry || (level > 0 && nritems == 0) {
            return Err(bad("item count out of range"));
        }
        Ok(Node { data, level, nritems })
    }

    pub fn key(&self, i: usize) -> Key {
        let entry = if self.level == 0 { ITEM } else { KEY_PTR };
        Key::parse(&self.data, HEADER + i * entry)
    }

    /// The data of leaf item `i`: it must lie after the item headers and inside the block.
    pub fn item(&self, i: usize) -> Option<&[u8]> {
        let at = HEADER + i * ITEM;
        let offset = le32(&self.data, at + 17) as usize;
        let size = le32(&self.data, at + 21) as usize;
        let start = HEADER.checked_add(offset)?;
        let end = start.checked_add(size)?;
        (start >= HEADER + self.nritems * ITEM && end <= self.data.len()).then(|| &self.data[start..end])
    }

    fn child(&self, i: usize) -> u64 {
        le64(&self.data, HEADER + i * KEY_PTR + 17)
    }

    /// The number of keys ordered before `key`, or at or before it with `inclusive`.
    fn count(&self, key: Key, inclusive: bool) -> usize {
        let (mut lo, mut hi) = (0, self.nritems);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let k = self.key(mid);
            if k < key || (inclusive && k == key) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

/// Where a tree's root block is.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Root {
    pub bytenr: u64,
    pub level: u8,
    /// The tree id its blocks must name as owner, for the trees whose blocks are never shared.
    pub owner: Option<u64>,
}

/// Per-operation state: decoded nodes and a work budget that stops a looping or absurdly
/// large structure.
pub(crate) struct Cache {
    nodes: HashMap<u64, Rc<Node>>,
    bytes: usize,
    budget: u64,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { nodes: HashMap::new(), bytes: 0, budget: FETCH_BUDGET }
    }

    pub fn exhausted(&self) -> bool {
        self.budget == 0
    }
}

/// What a tree block is read with.
#[derive(Clone, Copy)]
pub(crate) struct Disk<'a> {
    pub img: &'a dyn ReadAt,
    pub chunks: &'a Chunks,
    pub nodesize: usize,
    /// The id tree blocks carry: the filesystem's metadata uuid.
    pub fsid: &'a [u8; 16],
}

/// Called with each leaf item's key and data; returns whether to continue.
pub(crate) type Visit<'v> = dyn FnMut(Key, &[u8]) -> Result<bool> + 'v;

impl Disk<'_> {
    fn fetch(&self, cache: &mut Cache, bytenr: u64, owner: Option<u64>) -> Result<Rc<Node>> {
        cache.budget =
            cache.budget.checked_sub(1).ok_or_else(|| Error::corrupt("B-tree walk exceeded its work budget"))?;
        if let Some(node) = cache.nodes.get(&bytenr) {
            return Ok(node.clone());
        }
        let mut data = vec![0u8; self.nodesize];
        self.chunks.read(self.img, bytenr, &mut data)?;
        let node = Rc::new(Node::parse(data, bytenr, self.fsid, owner)?);
        if cache.bytes + self.nodesize > CACHE_BYTES {
            cache.nodes.clear();
            cache.bytes = 0;
        }
        cache.bytes += self.nodesize;
        cache.nodes.insert(bytenr, node.clone());
        Ok(node)
    }

    fn child_of(
        &self,
        cache: &mut Cache,
        root: Root,
        node: &Node,
        i: usize,
        seen: &mut HashSet<u64>,
    ) -> Result<Rc<Node>> {
        let ptr = node.child(i);
        if !seen.insert(ptr) {
            return Err(Error::corrupt(format!("tree block {ptr:#x} reached twice")));
        }
        let child = self.fetch(cache, ptr, root.owner)?;
        if child.level.checked_add(1) != Some(node.level) {
            return Err(Error::corrupt(format!("tree block {ptr:#x}: levels out of order")));
        }
        Ok(child)
    }

    /// Visits leaf items in key order from the first key at or after `start`, or from the
    /// last key at or before it with `include_prev`. Stops when `visit` returns `false`. A
    /// block reached twice in one scan is damage: the scan ends with an error.
    pub fn scan(&self, cache: &mut Cache, root: Root, start: Key, include_prev: bool, visit: &mut Visit) -> Result<()> {
        let mut stack: Vec<(Rc<Node>, usize)> = Vec::new();
        let mut seen = HashSet::from([root.bytenr]);
        let mut node = self.fetch(cache, root.bytenr, root.owner)?;
        if node.level != root.level {
            return Err(Error::corrupt(format!(
                "tree root {:#x}: level {} instead of {}",
                root.bytenr, node.level, root.level
            )));
        }
        while node.level > 0 {
            // The child whose key range holds `start`: the last key at or before it.
            let i = node.count(start, true).saturating_sub(1);
            let child = self.child_of(cache, root, &node, i, &mut seen)?;
            stack.push((node, i));
            node = child;
        }
        let mut i = if include_prev { node.count(start, true).saturating_sub(1) } else { node.count(start, false) };
        loop {
            while i < node.nritems {
                if let Some(data) = node.item(i) {
                    if !visit(node.key(i), data)? {
                        return Ok(());
                    }
                }
                i += 1;
            }
            // Climb to the nearest ancestor with a next child, then descend its leftmost path.
            let (mut parent, mut idx) = loop {
                match stack.pop() {
                    None => return Ok(()),
                    Some((parent, idx)) if idx + 1 < parent.nritems => break (parent, idx + 1),
                    Some(_) => {}
                }
            };
            loop {
                let child = self.child_of(cache, root, &parent, idx, &mut seen)?;
                stack.push((parent, idx));
                if child.level == 0 {
                    node = child;
                    break;
                }
                (parent, idx) = (child, 0);
            }
            i = 0;
        }
    }

    /// The data of the item with exactly this key.
    pub fn get(&self, cache: &mut Cache, root: Root, key: Key) -> Result<Option<Vec<u8>>> {
        let mut found = None;
        self.scan(cache, root, key, false, &mut |k, data| {
            if k == key {
                found = Some(data.to_vec());
            }
            Ok(false)
        })?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(length: u64, kind: u64, stripes: &[(u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 48 + 32 * stripes.len()];
        b[0..8].copy_from_slice(&length.to_le_bytes());
        b[24..32].copy_from_slice(&kind.to_le_bytes());
        b[44..46].copy_from_slice(&(stripes.len() as u16).to_le_bytes());
        for (i, (dev, off)) in stripes.iter().enumerate() {
            b[48 + 32 * i..56 + 32 * i].copy_from_slice(&dev.to_le_bytes());
            b[56 + 32 * i..64 + 32 * i].copy_from_slice(&off.to_le_bytes());
        }
        b
    }

    #[test]
    fn chunks_map_single_dup_and_refuse_the_rest() {
        let mut c = Chunks::new(1, 1 << 30);
        c.add(1 << 20, &chunk(1 << 20, 0, &[(1, 8 << 20)])).unwrap();
        c.add(4 << 20, &chunk(1 << 20, DUP, &[(1, 20 << 20), (1, 30 << 20)])).unwrap();
        c.add(8 << 20, &chunk(1 << 20, RAID1, &[(2, 0), (1, 40 << 20)])).unwrap();
        c.add(16 << 20, &chunk(1 << 20, RAID5, &[(1, 50 << 20), (2, 0), (3, 0)])).unwrap();
        c.add(32 << 20, &chunk(1 << 20, 0, &[(2, 0)])).unwrap();
        c.add(64 << 20, &chunk(1 << 20, 0, &[(1, (1 << 30) - 4096)])).unwrap();
        assert_eq!(c.map((1 << 20) + 5, 10).unwrap(), ((8 << 20) + 5, 10));
        assert_eq!(c.map((2 << 20) - 4, 10).unwrap(), ((9 << 20) - 4, 4));
        assert_eq!(c.map(4 << 20, 1).unwrap(), (20 << 20, 1));
        assert_eq!(c.map(8 << 20, 1).unwrap(), (40 << 20, 1));
        assert!(matches!(c.map(16 << 20, 1), Err(Error::Unsupported(m)) if m.contains("RAID5")));
        assert!(matches!(c.map(32 << 20, 1), Err(Error::Unsupported(m)) if m.contains("multi-device")));
        assert!(matches!(c.map(64 << 20, 8192), Err(Error::Corrupt(_))));
        assert!(matches!(c.map(3 << 20, 1), Err(Error::Corrupt(_))));
        assert_eq!(c.unreadable_profiles(), ["RAID5", "on another device"]);
        // Overlaps, overflows and absurd stripe counts are refused; a repeat replaces.
        assert!(c.add((1 << 20) + 4096, &chunk(4096, 0, &[(1, 0)])).is_err());
        assert!(c.add(u64::MAX - 10, &chunk(4096, 0, &[(1, 0)])).is_err());
        assert!(c.add(100 << 20, &chunk(4096, 0, &[])).is_err());
        assert!(c.add(100 << 20, &chunk(4096, 0, &[(1, 0)])[..60]).is_err());
        c.add(1 << 20, &chunk(1 << 20, 0, &[(1, 9 << 20)])).unwrap();
        assert_eq!(c.map(1 << 20, 1).unwrap(), (9 << 20, 1));
        assert_eq!(c.list.len(), 6);
    }

    #[test]
    fn keys_order_like_the_kernel() {
        assert!(Key::new(1, 200, 0) < Key::new(2, 0, 0));
        assert!(Key::new(1, 1, u64::MAX) < Key::new(1, 2, 0));
        assert!(Key::new(1, 1, 1) < Key::new(1, 1, 2));
    }
}

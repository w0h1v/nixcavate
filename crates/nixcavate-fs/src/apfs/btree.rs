//! Objects, B-tree nodes, object maps and the B-tree cursor ("Objects", "Object Maps" and
//! "B-Trees" in the Apple File System Reference).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::{le16, le32, le64, Error, ReadAt, Result};

pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJECT_TYPE_MASK: u32 = 0x0000_ffff;
pub(crate) const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x1;
const OBJECT_TYPE_BTREE: u32 = 0x2;
const OBJECT_TYPE_BTREE_NODE: u32 = 0x3;
pub(crate) const OBJECT_TYPE_OMAP: u32 = 0xb;
pub(crate) const OBJECT_TYPE_FS: u32 = 0xd;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
/// `btree_node_phys_t` header; the table of contents starts after it.
const NODE_HEADER: usize = 56;
/// `btree_info_t`, at the end of a root node.
const BTREE_INFO: usize = 40;
const OMAP_VAL_DELETED: u32 = 0x1;

/// Deeper trees than this are treated as corrupt (real trees are a handful of levels deep).
const MAX_DEPTH: usize = 16;
/// Decoded nodes kept per operation before the cache is dropped and refilled.
const CACHE_NODES: usize = 8192;
const CACHE_OIDS: usize = 1 << 20;
/// Node fetches (cache hits included) one operation may make: per node a walk reports, one
/// inode lookup (at most `MAX_DEPTH` levels plus a few leaves) and its share of directory
/// scans fit many times over.
const FETCH_BUDGET: u64 = crate::MAX_NODES * 64;

/// The Fletcher-64 checksum of `obj_phys_t`, computed over everything after the checksum field.
fn fletcher64(data: &[u8]) -> u64 {
    const MOD: u64 = 0xffff_ffff;
    // Reducing once per 16 KiB instead of per word gives the same sums: unreduced, sum1 stays
    // below 2^44 and sum2 below 2^56 over 4096 words.
    let (mut sum1, mut sum2) = (0u64, 0u64);
    for chunk in data.chunks(16384) {
        for word in chunk.chunks_exact(4) {
            sum1 += u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
            sum2 += sum1;
        }
        sum1 %= MOD;
        sum2 %= MOD;
    }
    let c1 = MOD - (sum1 + sum2) % MOD;
    let c2 = MOD - (sum1 + c1) % MOD;
    (c2 << 32) | c1
}

pub(crate) fn checksum_ok(block: &[u8]) -> bool {
    block.len() > 8 && le64(block, 0) == fletcher64(&block[8..])
}

pub(crate) fn object_type(block: &[u8]) -> u32 {
    le32(block, 24) & OBJECT_TYPE_MASK
}

/// The container's blocks.
#[derive(Clone, Copy)]
pub(crate) struct Disk<'a> {
    pub img: &'a dyn ReadAt,
    pub bs: u64,
    /// Blocks that exist both in the superblock's count and in the image.
    pub blocks: u64,
}

impl Disk<'_> {
    pub fn block(&self, paddr: u64) -> Result<Vec<u8>> {
        if paddr >= self.blocks {
            return Err(Error::corrupt(format!("block {paddr} is past the end of the container")));
        }
        let mut buf = vec![0u8; self.bs as usize];
        self.img.read_at(paddr * self.bs, &mut buf)?;
        Ok(buf)
    }

    /// A physical object of type `ty` with a valid checksum.
    pub fn object(&self, paddr: u64, ty: u32) -> Result<Vec<u8>> {
        let block = self.block(paddr)?;
        if !checksum_ok(&block) {
            return Err(Error::corrupt(format!("bad checksum on object at block {paddr}")));
        }
        if object_type(&block) != ty {
            return Err(Error::corrupt(format!("object at block {paddr} is not of type {ty:#x}")));
        }
        Ok(block)
    }
}

/// A decoded `btree_node_phys_t`.
pub(crate) struct Node {
    data: Vec<u8>,
    pub level: u16,
    pub nkeys: usize,
    /// Key and value sizes for trees with fixed-size entries.
    fixed: Option<(usize, usize)>,
    toc: usize,
    keys: usize,
    vals_end: usize,
}

impl Node {
    fn parse(data: Vec<u8>, kv: (usize, usize)) -> Result<Node> {
        let bad = || Error::corrupt("malformed B-tree node");
        let flags = le16(&data, 32);
        let level = le16(&data, 34);
        let nkeys = le32(&data, 36) as usize;
        let toc = NODE_HEADER + usize::from(le16(&data, 40));
        let toc_len = usize::from(le16(&data, 42));
        let keys = toc + toc_len;
        let vals_end = data.len().checked_sub(if flags & BTNODE_ROOT != 0 { BTREE_INFO } else { 0 }).ok_or_else(bad)?;
        let fixed = flags & BTNODE_FIXED_KV_SIZE != 0;
        let entry = if fixed { 4 } else { 8 };
        if keys > vals_end || nkeys.checked_mul(entry).is_none_or(|n| n > toc_len) {
            return Err(bad());
        }
        if (flags & BTNODE_LEAF != 0) != (level == 0) || (fixed && kv.0 == 0) {
            return Err(bad());
        }
        Ok(Node { data, level, nkeys, fixed: fixed.then_some(kv), toc, keys, vals_end })
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn key(&self, i: usize) -> Option<&[u8]> {
        if i >= self.nkeys {
            return None;
        }
        let (off, len) = match self.fixed {
            Some((klen, _)) => (le16(&self.data, self.toc + 4 * i), klen),
            None => (le16(&self.data, self.toc + 8 * i), usize::from(le16(&self.data, self.toc + 8 * i + 2))),
        };
        let start = self.keys + usize::from(off);
        let end = start + len;
        (end <= self.vals_end).then(|| &self.data[start..end])
    }

    pub fn val(&self, i: usize) -> Option<&[u8]> {
        if i >= self.nkeys {
            return None;
        }
        let (off, len) = match self.fixed {
            Some((_, vlen)) => (le16(&self.data, self.toc + 4 * i + 2), if self.is_leaf() { vlen } else { 8 }),
            None => (le16(&self.data, self.toc + 8 * i + 4), usize::from(le16(&self.data, self.toc + 8 * i + 6))),
        };
        let start = self.vals_end.checked_sub(usize::from(off))?;
        let end = start.checked_add(len)?;
        (start >= self.keys && end <= self.vals_end).then(|| &self.data[start..end])
    }

    fn child(&self, i: usize) -> Result<u64> {
        let val = self.val(i).filter(|v| v.len() >= 8);
        val.map(|v| le64(v, 0)).ok_or_else(|| Error::corrupt("B-tree index entry without a child"))
    }

    /// The number of leading keys that sort before the target (`cmp` gives key vs target).
    fn count_less(&self, cmp: &dyn Fn(&[u8]) -> Ordering) -> usize {
        let (mut lo, mut hi) = (0, self.nkeys);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.key(mid).is_none_or(|k| cmp(k) == Ordering::Less) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

/// Called with each leaf entry's key and value; returns whether to continue.
pub(crate) type Visit<'v> = dyn FnMut(&[u8], &[u8]) -> Result<bool> + 'v;

/// Where a B-tree lives and how its entries are laid out.
#[derive(Clone, Copy)]
pub(crate) struct Tree {
    pub root: u64,
    /// Child pointers are physical block numbers rather than virtual object ids.
    pub physical: bool,
    /// Key and value sizes when the nodes use fixed-size entries.
    pub kv: (usize, usize),
}

/// Per-operation state: decoded nodes, translated object ids and a work budget that stops
/// a looping or absurdly large structure.
pub(crate) struct Cache {
    nodes: HashMap<u64, Rc<Node>>,
    oids: HashMap<u64, u64>,
    budget: u64,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { nodes: HashMap::new(), oids: HashMap::new(), budget: FETCH_BUDGET }
    }

    pub fn exhausted(&self) -> bool {
        self.budget == 0
    }
}

/// Resolves objects for one container or volume: virtual ids through `omap` as of `xid`.
#[derive(Clone, Copy)]
pub(crate) struct Ctx<'a> {
    pub disk: Disk<'a>,
    /// Root node of the object map's B-tree.
    pub omap: Option<u64>,
    pub xid: u64,
}

impl Ctx<'_> {
    fn fetch(&self, cache: &mut Cache, ptr: u64, physical: bool, kv: (usize, usize)) -> Result<Rc<Node>> {
        cache.budget =
            cache.budget.checked_sub(1).ok_or_else(|| Error::corrupt("B-tree walk exceeded its work budget"))?;
        let paddr = if physical { ptr } else { self.translate(cache, ptr)? };
        if let Some(node) = cache.nodes.get(&paddr) {
            return Ok(node.clone());
        }
        let data = self.disk.block(paddr)?;
        let ty = object_type(&data);
        if !checksum_ok(&data) || !(ty == OBJECT_TYPE_BTREE || ty == OBJECT_TYPE_BTREE_NODE) || le64(&data, 8) != ptr {
            return Err(Error::corrupt(format!("block {paddr} is not a valid B-tree node")));
        }
        let node = Rc::new(Node::parse(data, kv)?);
        if cache.nodes.len() >= CACHE_NODES {
            cache.nodes.clear();
        }
        cache.nodes.insert(paddr, node.clone());
        Ok(node)
    }

    /// The physical address of virtual object `oid`: the object-map entry with the newest
    /// transaction id not after ours.
    pub fn translate(&self, cache: &mut Cache, oid: u64) -> Result<u64> {
        if let Some(&paddr) = cache.oids.get(&oid) {
            return Ok(paddr);
        }
        let root = self.omap.ok_or_else(|| Error::corrupt("virtual object without an object map"))?;
        let target = (oid, self.xid);
        let cmp = |k: &[u8]| if k.len() < 16 { Ordering::Less } else { (le64(k, 0), le64(k, 8)).cmp(&target) };
        let missing = || Error::corrupt(format!("object {oid:#x} is not in the object map"));
        let mut node = self.fetch(cache, root, true, (16, 16))?;
        for _ in 0..MAX_DEPTH {
            // The last entry at or before (oid, xid).
            let i = node.count_less(&|k| if cmp(k) == Ordering::Greater { Ordering::Greater } else { Ordering::Less });
            let i = i.checked_sub(1).ok_or_else(missing)?;
            if node.is_leaf() {
                let key = node.key(i).ok_or_else(missing)?;
                let val = node.val(i).filter(|v| v.len() >= 16).ok_or_else(missing)?;
                if le64(key, 0) != oid || le32(val, 0) & OMAP_VAL_DELETED != 0 {
                    return Err(missing());
                }
                let paddr = le64(val, 8);
                if cache.oids.len() >= CACHE_OIDS {
                    cache.oids.clear();
                }
                cache.oids.insert(oid, paddr);
                return Ok(paddr);
            }
            let child = self.fetch(cache, node.child(i)?, true, (16, 16))?;
            if child.level.checked_add(1) != Some(node.level) {
                return Err(Error::corrupt("object map B-tree levels out of order"));
            }
            node = child;
        }
        Err(Error::corrupt("object map B-tree too deep"))
    }

    /// Checks that the tree's root node can be read.
    pub fn check_root(&self, cache: &mut Cache, tree: Tree) -> Result<()> {
        self.fetch(cache, tree.root, tree.physical, tree.kv).map(|_| ())
    }

    /// Visits leaf entries in key order, starting at the first key not before the target
    /// (`cmp` orders a key against the target), or at the entry just before it when
    /// `include_prev` is set. Stops when `visit` returns `false`. A node reached twice in one
    /// scan (index entries that repeat a child) is damage: the scan ends with an error.
    pub fn scan(
        &self,
        cache: &mut Cache,
        tree: Tree,
        cmp: &dyn Fn(&[u8]) -> Ordering,
        include_prev: bool,
        visit: &mut Visit,
    ) -> Result<()> {
        let mut stack: Vec<(Rc<Node>, usize)> = Vec::new();
        let mut seen = HashSet::from([tree.root]);
        let mut node = self.fetch(cache, tree.root, tree.physical, tree.kv)?;
        while !node.is_leaf() {
            if stack.len() >= MAX_DEPTH {
                return Err(Error::corrupt("B-tree too deep"));
            }
            let i = node.count_less(cmp).saturating_sub(1);
            let child = self.child_of(cache, tree, &node, i, &mut seen)?;
            stack.push((node, i));
            node = child;
        }
        let mut i = node.count_less(cmp);
        if include_prev {
            i = i.saturating_sub(1);
        }
        loop {
            while i < node.nkeys {
                if let (Some(k), Some(v)) = (node.key(i), node.val(i)) {
                    if !visit(k, v)? {
                        return Ok(());
                    }
                }
                i += 1;
            }
            // Climb to the nearest ancestor with a next child, then descend its leftmost path.
            let (mut parent, mut idx) = loop {
                match stack.pop() {
                    None => return Ok(()),
                    Some((parent, idx)) if idx + 1 < parent.nkeys => break (parent, idx + 1),
                    Some(_) => {}
                }
            };
            loop {
                let child = self.child_of(cache, tree, &parent, idx, &mut seen)?;
                stack.push((parent, idx));
                if child.is_leaf() {
                    node = child;
                    break;
                }
                (parent, idx) = (child, 0);
            }
            i = 0;
        }
    }

    fn child_of(
        &self,
        cache: &mut Cache,
        tree: Tree,
        node: &Node,
        i: usize,
        seen: &mut HashSet<u64>,
    ) -> Result<Rc<Node>> {
        let ptr = node.child(i)?;
        if !seen.insert(ptr) {
            return Err(Error::corrupt(format!("B-tree node {ptr:#x} reached twice")));
        }
        let child = self.fetch(cache, ptr, tree.physical, tree.kv)?;
        if child.level.checked_add(1) != Some(node.level) {
            return Err(Error::corrupt("B-tree levels out of order"));
        }
        Ok(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fletcher_matches_a_known_zero_block() {
        // All-zero data gives sums of zero, so both check words are 0xffffffff.
        assert_eq!(fletcher64(&[0u8; 64]), 0xffff_ffff_ffff_ffff);
        let mut block = vec![0u8; 4096];
        block[8..12].copy_from_slice(&7u32.to_le_bytes());
        let sum = fletcher64(&block[8..]);
        block[..8].copy_from_slice(&sum.to_le_bytes());
        assert!(checksum_ok(&block));
        block[100] = 1;
        assert!(!checksum_ok(&block));
    }
}

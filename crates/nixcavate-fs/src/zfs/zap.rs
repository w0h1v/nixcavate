//! ZAP objects, the name-value maps behind directories, properties and the pool's object
//! directory (OpenZFS `zap_impl.h`, `zap_leaf.h`, `zap_micro.c`, `zap_leaf.c`).
//!
//! A microzap is one block of 64-byte entries: a 64-bit value and a name of at most 49
//! bytes. A fat ZAP has a header block, a pointer table (inside the header block or in blocks
//! of its own) naming leaf blocks, and leaves of 24-byte chunks: entry chunks pointing at
//! chains of array chunks that hold the name and the value. Every entry chunk of every leaf
//! the table names is read; the hash chains are not followed, so a looping chain cannot
//! matter. Array chains are followed only as far as the bytes they must hold.

use std::collections::BTreeSet;

use super::block::{u16e, u32e, u64e, Cache, Dnode, Pool};
use crate::{Error, ReadAt, Result};

const ZBT_LEAF: u64 = 1 << 63;
const ZBT_HEADER: u64 = (1 << 63) + 1;
const ZBT_MICRO: u64 = (1 << 63) + 3;
const ZAP_MAGIC: u64 = 0x2_f52a_b2ab;
const LEAF_MAGIC: u32 = 0x02ab_1eaf;
const CHUNK: usize = 24;
const CHUNK_ENTRY: u8 = 252;
const CHUNK_ARRAY: u8 = 251;
const ARRAY_BYTES: usize = 21;
const FLAG_UINT64_KEY: u64 = 1 << 1;
/// The longest value read (property strings, SA layouts and directory entries are far
/// smaller); a longer one is skipped as damaged.
const MAX_VALUE: usize = 64 << 10;
/// Leaf blocks one fat ZAP may have.
const MAX_LEAVES: usize = 1 << 22;

/// One entry's value: `len`-byte integers, packed big-endian.
pub(crate) struct Value {
    pub int_len: usize,
    pub bytes: Vec<u8>,
}

impl Value {
    /// The first integer.
    pub fn first(&self) -> Option<u64> {
        let b = self.bytes.get(..self.int_len)?;
        (1..=8).contains(&self.int_len).then(|| b.iter().fold(0u64, |v, &x| v << 8 | u64::from(x)))
    }

    /// Every integer.
    pub fn ints(&self) -> Vec<u64> {
        if !(1..=8).contains(&self.int_len) {
            return Vec::new();
        }
        self.bytes.chunks_exact(self.int_len).map(|c| c.iter().fold(0u64, |v, &x| v << 8 | u64::from(x))).collect()
    }

    /// A string value, without its terminating NUL.
    pub fn string(&self) -> Option<String> {
        if self.int_len != 1 {
            return None;
        }
        let b = self.bytes.strip_suffix(&[0]).unwrap_or(&self.bytes);
        Some(String::from_utf8_lossy(b).into_owned())
    }
}

/// Calls `visit` with each entry's name and value until it returns false. Returns the
/// number of damaged entries skipped.
pub(crate) fn list<R: ReadAt>(
    pool: &Pool<R>,
    cache: &mut Cache,
    dn: &Dnode,
    visit: &mut dyn FnMut(&[u8], Value) -> bool,
) -> Result<usize> {
    let head = dn.block(pool, cache, 0)?.ok_or_else(|| Error::corrupt("ZAP without its first block"))?;
    let le = head.le;
    match u64e(&head.data, 0, le) {
        ZBT_MICRO => {
            for entry in head.data.chunks_exact(64).skip(1) {
                let name = &entry[14..64];
                let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
                if name.is_empty() {
                    continue;
                }
                let value = Value { int_len: 8, bytes: u64e(entry, 0, le).to_be_bytes().to_vec() };
                if !visit(name, value) {
                    break;
                }
            }
            Ok(0)
        }
        ZBT_HEADER => fat(pool, cache, dn, &head.data, le, visit),
        t => Err(Error::corrupt(format!("ZAP block type {t:#x}"))),
    }
}

/// The value of entry `name`.
pub(crate) fn lookup<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, dn: &Dnode, name: &[u8]) -> Result<Option<Value>> {
    let mut found = None;
    list(pool, cache, dn, &mut |n, v| {
        if n == name {
            found = Some(v);
        }
        found.is_none()
    })?;
    Ok(found)
}

fn fat<R: ReadAt>(
    pool: &Pool<R>,
    cache: &mut Cache,
    dn: &Dnode,
    head: &[u8],
    le: bool,
    visit: &mut dyn FnMut(&[u8], Value) -> bool,
) -> Result<usize> {
    let bad = |what: &str| Error::corrupt(format!("fat ZAP: {what}"));
    if u64e(head, 8, le) != ZAP_MAGIC {
        return Err(bad("no magic"));
    }
    let bsize = head.len();
    if !bsize.is_power_of_two() || bsize < 512 {
        return Err(bad("block size is not a power of two"));
    }
    let shift = bsize.trailing_zeros() as usize;
    let (tbl_blk, tbl_blocks, tbl_shift) = (u64e(head, 16, le), u64e(head, 24, le), u64e(head, 32, le));
    let flags = u64e(head, 96, le);
    let blocks = dn.maxblkid.saturating_add(1);
    // The pointer table: leaf block numbers, each repeated for the hash prefixes it serves.
    let mut leaves = BTreeSet::new();
    let mut add = |blk: u64| -> Result<()> {
        if blk == 0 || blk >= blocks {
            return Err(bad("pointer table names a block outside the object"));
        }
        if leaves.len() >= MAX_LEAVES {
            return Err(bad("too many leaves"));
        }
        leaves.insert(blk);
        Ok(())
    };
    if tbl_blocks == 0 {
        // Embedded: the second half of the header block.
        if tbl_shift != (shift - 4) as u64 {
            return Err(bad("embedded pointer table of the wrong size"));
        }
        for i in 0..1usize << (shift - 4) {
            add(u64e(head, bsize / 2 + 8 * i, le))?;
        }
    } else {
        let per = (bsize / 8) as u64;
        if tbl_shift > 40 || tbl_blocks.checked_mul(per).is_none_or(|n| n < 1 << tbl_shift) {
            return Err(bad("pointer table smaller than its entries"));
        }
        if tbl_blk.checked_add(tbl_blocks).is_none_or(|end| end > blocks) {
            return Err(bad("pointer table outside the object"));
        }
        let entries = 1u64 << tbl_shift;
        for b in 0..entries.div_ceil(per) {
            let block = dn.block(pool, cache, tbl_blk + b)?.ok_or_else(|| bad("pointer table block is a hole"))?;
            let n = (entries - b * per).min(per) as usize;
            for i in 0..n {
                add(u64e(&block.data, 8 * i, block.le))?;
            }
        }
    }
    let key_len = if flags & FLAG_UINT64_KEY != 0 { 8 } else { 1 };
    let mut damaged = 0usize;
    for blk in leaves {
        let Some(leaf) = dn.block(pool, cache, blk)? else {
            damaged += 1;
            continue;
        };
        let (data, le) = (&leaf.data, leaf.le);
        if data.len() != bsize || u64e(data, 0, le) != ZBT_LEAF || u32e(data, 24, le) != LEAF_MAGIC {
            damaged += 1;
            continue;
        }
        let hash_entries = 1usize << (shift - 5);
        let first = 48 + 2 * hash_entries;
        let count = ((bsize - 2 * hash_entries) / CHUNK).saturating_sub(2);
        let chunk = |i: usize| data.get(first + CHUNK * i..first + CHUNK * (i + 1));
        // The bytes of the array chain starting at chunk `i`.
        let array = |mut i: usize, len: usize| -> Option<Vec<u8>> {
            if len > MAX_VALUE {
                return None;
            }
            let mut out = Vec::with_capacity(len);
            while out.len() < len {
                let c = chunk(i).filter(|_| i < count)?;
                if c[0] != CHUNK_ARRAY {
                    return None;
                }
                let n = (len - out.len()).min(ARRAY_BYTES);
                out.extend_from_slice(&c[1..1 + n]);
                i = usize::from(u16e(c, 22, le));
            }
            Some(out)
        };
        for i in 0..count {
            let Some(c) = chunk(i) else { break };
            if c[0] != CHUNK_ENTRY {
                continue;
            }
            let int_len = usize::from(c[1]);
            let (name_chunk, name_ints) = (usize::from(u16e(c, 4, le)), usize::from(u16e(c, 6, le)));
            let (value_chunk, value_ints) = (usize::from(u16e(c, 8, le)), usize::from(u16e(c, 10, le)));
            let name = array(name_chunk, name_ints * key_len);
            let value = array(value_chunk, value_ints * int_len);
            let (Some(name), Some(bytes)) = (name, value) else {
                damaged += 1;
                continue;
            };
            let name = if key_len == 1 { name.strip_suffix(&[0]).unwrap_or(&name).to_vec() } else { name };
            if !visit(&name, Value { int_len, bytes }) {
                return Ok(damaged);
            }
        }
    }
    Ok(damaged)
}

#[cfg(test)]
mod tests {
    use super::super::block::testing::{bp, dnode, pool};
    use super::*;

    #[test]
    fn big_endian_microzap() {
        let mut block = vec![0u8; 512];
        block[..8].copy_from_slice(&ZBT_MICRO.to_be_bytes());
        block[64..72].copy_from_slice(&42u64.to_be_bytes());
        block[78..82].copy_from_slice(b"ROOT");
        let pool = pool(&[(0, block)]);
        let dn = dnode(21, 1, 512, 0, &[bp(0, 512, 21, 0, false)], false);
        let v = lookup(&pool, &mut Cache::new(), &dn, b"ROOT").unwrap().unwrap();
        assert_eq!(v.first(), Some(42));
    }

    #[test]
    fn looping_array_chains_end() {
        // A 512-byte fat ZAP: the header with its embedded pointer table naming leaf 1, and a
        // leaf whose one entry's name chain points at itself.
        let mut head = vec![0u8; 512];
        head[..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        head[8..16].copy_from_slice(&ZAP_MAGIC.to_le_bytes());
        head[32..40].copy_from_slice(&5u64.to_le_bytes());
        for i in 0..32 {
            head[256 + 8 * i..264 + 8 * i].copy_from_slice(&1u64.to_le_bytes());
        }
        let mut leaf = vec![0u8; 512];
        leaf[..8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        leaf[24..28].copy_from_slice(&LEAF_MAGIC.to_le_bytes());
        let chunk = |i: usize| 80 + 24 * i;
        let e = chunk(0);
        (leaf[e], leaf[e + 1]) = (CHUNK_ENTRY, 8);
        leaf[e + 4..e + 6].copy_from_slice(&1u16.to_le_bytes());
        leaf[e + 6..e + 8].copy_from_slice(&60000u16.to_le_bytes());
        leaf[e + 8..e + 10].copy_from_slice(&2u16.to_le_bytes());
        leaf[e + 10..e + 12].copy_from_slice(&1u16.to_le_bytes());
        let a = chunk(1);
        leaf[a] = CHUNK_ARRAY;
        leaf[a + 1..a + 22].fill(b'x');
        leaf[a + 22..a + 24].copy_from_slice(&1u16.to_le_bytes());
        let v = chunk(2);
        leaf[v] = CHUNK_ARRAY;
        leaf[v + 8] = 7;
        leaf[v + 22..v + 24].copy_from_slice(&0xffffu16.to_le_bytes());
        let pool = pool(&[(0, head), (512, leaf)]);
        let dn = dnode(20, 1, 512, 1, &[bp(0, 512, 20, 0, true), bp(512, 512, 20, 0, true)], true);
        let mut names = Vec::new();
        let damaged = list(&pool, &mut Cache::new(), &dn, &mut |n, v| {
            names.push((n.len(), v.first()));
            true
        })
        .unwrap();
        // The name is cut at the 64 KiB value limit only after the chain is followed that far;
        // here 60000 bytes are read from the one chunk, never forever.
        assert_eq!((names, damaged), (vec![(60000, Some(7))], 0));
    }

    #[test]
    fn values() {
        let v = Value { int_len: 8, bytes: vec![0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 3] };
        assert_eq!((v.first(), v.ints()), (Some(0x102), vec![0x102, 3]));
        let s = Value { int_len: 1, bytes: b"/usr\0".to_vec() };
        assert_eq!(s.string().as_deref(), Some("/usr"));
        let layout = Value { int_len: 2, bytes: vec![0, 5, 0, 6] };
        assert_eq!(layout.ints(), [5, 6]);
        assert_eq!(Value { int_len: 0, bytes: vec![] }.first(), None);
        assert_eq!(Value { int_len: 9, bytes: vec![0; 9] }.ints(), Vec::<u64>::new());
    }
}

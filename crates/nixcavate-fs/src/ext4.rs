//! ext2, ext3 and ext4, read-only.
//!
//! Written from the Linux kernel documentation "ext4 Data Structures and Algorithms"
//! (docs.kernel.org/filesystems/ext4/): super block, block group descriptors, inode table,
//! `i_block` contents, extent tree, directory entries, inline data and extended attributes.
//!
//! Supported:
//! - Block sizes 1 KiB to 64 KiB, 32- and 64-byte group descriptors (`64bit`), `meta_bg`,
//!   `flex_bg`, `sparse_super` and `sparse_super2` (for locating `meta_bg` descriptors).
//! - Inodes of 128 bytes and larger: 32-bit uid/gid, 64-bit size, nanosecond times with the
//!   34-bit seconds extension, and the creation time when the inode has room for it.
//! - File data through extent trees (unwritten extents read as zeros), ext2/ext3 direct and
//!   indirect block maps, inline data (`i_block` plus the `system.data` attribute), sparse
//!   holes, and fast and slow symlinks.
//! - Linear, hash-tree and inline directories. Hash-tree interior blocks look like empty linear
//!   blocks, so every directory is read with a linear scan of all its blocks, one block at a
//!   time. A directory block belongs to one directory, so a walk reads each physical block
//!   once: a directory whose map names a block already read is listed up to that block.
//!
//! Not supported:
//! - Encrypted files and directories (reading one returns [`Error::Unsupported`]; the volume
//!   still opens), `compression`, `dirdata` and external journal devices (the volume is refused).
//! - Attribute values stored in their own inode (`ea_inode`) for inline data.
//! - The journal: a volume that needs recovery is read as it is on disk, without replay.
//! - Deleted-file recovery and extended attributes other than inline data.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use crate::{le16, le32, shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Tree, Volume, MAX_PATH};

const SUPERBLOCK_OFFSET: u64 = 1024;
const MAGIC: u16 = 0xEF53;

const COMPAT_SPARSE_SUPER2: u32 = 0x200;

const INCOMPAT_COMPRESSION: u32 = 0x1;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_DIRDATA: u32 = 0x1000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// recover, extents, mmp, flex_bg, ea_inode, csum_seed, inline_data, encrypt, casefold and the
/// flags above that do not change how this reader finds data.
const INCOMPAT_KNOWN: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x2000 | 0x4000 | 0x8000;
const INCOMPAT_KNOWN_HIGH: u32 = 0x10000 | 0x20000;

const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_HUGE_FILE: u32 = 0x8;
const RO_COMPAT_GDT_CSUM: u32 = 0x10;
const RO_COMPAT_METADATA_CSUM: u32 = 0x400;

const BG_INODE_UNINIT: u16 = 0x1;

const FL_ENCRYPT: u32 = 0x800;
const FL_HUGE_FILE: u32 = 0x4_0000;
const FL_EXTENTS: u32 = 0x8_0000;
const FL_INLINE_DATA: u32 = 0x1000_0000;

const EXTENT_MAGIC: u16 = 0xF30A;
const EXTENT_MAX_DEPTH: u16 = 5;
const XATTR_MAGIC: u32 = 0xEA02_0000;
const XATTR_INDEX_SYSTEM: u8 = 7;

/// Inode tables kept in memory at once, in bytes.
const TABLE_CACHE_BYTES: usize = 64 << 20;
/// The largest part of one group's inode table read in one go.
const TABLE_READ_MAX: usize = 32 << 20;

/// An opened ext2/3/4 volume.
pub struct Ext4<R> {
    image: R,
    block_size: u64,
    blocks_count: u64,
    inode_size: usize,
    inodes_per_group: u32,
    inodes_count: u32,
    incompat: u32,
    huge_file: bool,
    groups: Vec<Group>,
    /// Shared by concurrent reads; a table is read while the lock is held, so the cache never
    /// holds more than its byte budget plus the one table being added.
    tables: Mutex<TableCache>,
}

struct Group {
    inode_table: u64,
    /// Inodes at the start of the table that are read with the table and cached.
    cached: u32,
}

#[derive(Default)]
struct TableCache {
    map: HashMap<usize, Arc<[u8]>>,
    order: VecDeque<usize>,
    bytes: usize,
}

/// The parts of an inode this reader uses.
#[derive(Clone, Copy)]
struct Inode {
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    links: u16,
    flags: u32,
    blocks_lo: u32,
    /// Bytes allocated (`i_blocks`).
    allocated: u64,
    file_acl: u64,
    block: [u8; 60],
    accessed: Option<i64>,
    modified: Option<i64>,
    changed: Option<i64>,
    created: Option<i64>,
}

/// A run of logical blocks that maps to consecutive physical blocks, or a hole.
struct Run {
    phys: Option<u64>,
    len: u64,
}

/// Recently read extent-tree and indirect blocks, for one read.
struct Blocks {
    entries: Vec<(u64, Vec<u8>)>,
    next: usize,
}

fn superblock_ok(sb: &[u8]) -> bool {
    le16(sb, 0x38) == MAGIC && le32(sb, 0x18) <= 6 && le32(sb, 0x20) != 0 && le32(sb, 0x28) != 0 && le32(sb, 0) != 0
}

/// True when `image` starts with an ext2/3/4 superblock.
pub fn probe(image: &dyn ReadAt) -> bool {
    let mut sb = [0u8; 1024];
    image.read_at(SUPERBLOCK_OFFSET, &mut sb).is_ok() && superblock_ok(&sb)
}

/// Whether block group `g` holds a superblock backup (and so its descriptors follow one).
fn has_superblock(g: u64, sb: &[u8]) -> bool {
    let is_power = |mut n: u64, base: u64| {
        while n % base == 0 {
            n /= base;
        }
        n == 1
    };
    if g == 0 {
        true
    } else if le32(sb, 0x5C) & COMPAT_SPARSE_SUPER2 != 0 {
        g == u64::from(le32(sb, 0x24C)) || g == u64::from(le32(sb, 0x250))
    } else if le32(sb, 0x64) & RO_COMPAT_SPARSE_SUPER == 0 {
        true
    } else {
        g == 1 || is_power(g, 3) || is_power(g, 5) || is_power(g, 7)
    }
}

/// Decodes a 32-bit time and its `_extra` word (epoch bits and nanoseconds) into nanoseconds.
fn time(seconds: u32, extra: Option<u32>) -> Option<i64> {
    let mut secs = i64::from(seconds as i32);
    let mut nanos = 0;
    if let Some(extra) = extra {
        secs += i64::from(extra & 3) << 32;
        nanos = i64::from(extra >> 2);
        if nanos >= 1_000_000_000 {
            nanos = 0;
        }
    }
    if secs == 0 && nanos == 0 {
        return None;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

impl Inode {
    fn parse<R>(raw: &[u8], fs: &Ext4<R>) -> Inode {
        let extra_isize = if raw.len() > 128 { usize::from(le16(raw, 0x80)) } else { 0 };
        // An `_extra` field exists when the extra area covers it.
        let field = |off: usize| (off + 4 <= 128 + extra_isize && off + 4 <= raw.len()).then(|| le32(raw, off));
        let mode = le16(raw, 0);
        let mut size = u64::from(le32(raw, 0x4));
        // `i_size_high` holds file sizes, and directory sizes only with `largedir`.
        let large_dir = fs.incompat & INCOMPAT_LARGEDIR != 0;
        if mode & 0xF000 == 0x8000 || (mode & 0xF000 == 0x4000 && large_dir) {
            size |= u64::from(le32(raw, 0x6C)) << 32;
        }
        let flags = le32(raw, 0x20);
        let blocks_lo = le32(raw, 0x1C);
        let mut blocks = u64::from(blocks_lo);
        if fs.huge_file {
            blocks |= u64::from(le16(raw, 0x74)) << 32;
        }
        let unit = if fs.huge_file && flags & FL_HUGE_FILE != 0 { fs.block_size } else { 512 };
        let mut block = [0u8; 60];
        block.copy_from_slice(&raw[0x28..0x64]);
        Inode {
            mode,
            uid: u32::from(le16(raw, 0x2)) | u32::from(le16(raw, 0x78)) << 16,
            gid: u32::from(le16(raw, 0x18)) | u32::from(le16(raw, 0x7A)) << 16,
            size,
            links: le16(raw, 0x1A),
            flags,
            blocks_lo,
            allocated: blocks.saturating_mul(unit),
            file_acl: u64::from(le32(raw, 0x68)) | u64::from(le16(raw, 0x76)) << 32,
            block,
            accessed: time(le32(raw, 0x8), field(0x8C)),
            modified: time(le32(raw, 0x10), field(0x88)),
            changed: time(le32(raw, 0xC), field(0x84)),
            created: field(0x90).and_then(|secs| time(secs, field(0x94))),
        }
    }

    fn kind(&self) -> Kind {
        match self.mode & 0xF000 {
            0x8000 => Kind::File,
            0x4000 => Kind::Directory,
            0xA000 => Kind::Symlink,
            _ => Kind::Other,
        }
    }
}

impl Blocks {
    fn new() -> Self {
        Blocks { entries: Vec::new(), next: 0 }
    }

    fn get<R: ReadAt>(&mut self, fs: &Ext4<R>, block: u64) -> Result<&[u8]> {
        if let Some(i) = self.entries.iter().position(|(b, _)| *b == block) {
            return Ok(&self.entries[i].1);
        }
        let mut data = vec![0u8; fs.block_size as usize];
        fs.read_blocks(block, 1, 0, &mut data)?;
        let i = if self.entries.len() < 8 {
            self.entries.push((block, data));
            self.entries.len() - 1
        } else {
            let i = self.next;
            self.entries[i] = (block, data);
            self.next = (i + 1) % 8;
            i
        };
        Ok(&self.entries[i].1)
    }
}

impl<R: ReadAt> Ext4<R> {
    pub fn open(image: R) -> Result<Ext4<R>> {
        let mut sb = [0u8; 1024];
        image.read_at(SUPERBLOCK_OFFSET, &mut sb)?;
        if !superblock_ok(&sb) {
            return Err(Error::corrupt("no ext2/3/4 superblock"));
        }
        let incompat = le32(&sb, 0x60);
        if incompat & INCOMPAT_JOURNAL_DEV != 0 {
            return Err(Error::unsupported("ext4 external journal device, not a filesystem"));
        }
        if incompat & INCOMPAT_COMPRESSION != 0 {
            return Err(Error::unsupported("ext2 compression"));
        }
        if incompat & INCOMPAT_DIRDATA != 0 {
            return Err(Error::unsupported("ext4 dirdata directory entries"));
        }
        let unknown = incompat & !(INCOMPAT_KNOWN | INCOMPAT_KNOWN_HIGH);
        if unknown != 0 {
            return Err(Error::unsupported(format!("unknown ext4 incompatible features {unknown:#x}")));
        }
        let block_size = 1024u64 << le32(&sb, 0x18);
        let inode_size = if le32(&sb, 0x4C) == 0 { 128 } else { usize::from(le16(&sb, 0x58)) };
        if inode_size < 128 || !inode_size.is_power_of_two() || inode_size as u64 > block_size {
            return Err(Error::corrupt(format!("inode size {inode_size}")));
        }
        let inodes_count = le32(&sb, 0);
        let inodes_per_group = le32(&sb, 0x28);
        let blocks_per_group = u64::from(le32(&sb, 0x20));
        let first_data_block = u64::from(le32(&sb, 0x14));
        let is_64bit = incompat & INCOMPAT_64BIT != 0;
        let mut blocks_count = u64::from(le32(&sb, 0x4));
        let mut desc_size = 32;
        if is_64bit {
            blocks_count |= u64::from(le32(&sb, 0x150)) << 32;
            desc_size = u64::from(le16(&sb, 0xFE));
        }
        if desc_size < 32 || !desc_size.is_power_of_two() || desc_size > block_size {
            return Err(Error::corrupt(format!("group descriptor size {desc_size}")));
        }
        // Both counts give the number of groups; a forged one must not size the group table.
        let group_count = u64::from(inodes_count.div_ceil(inodes_per_group));
        let by_blocks = blocks_count.saturating_sub(first_data_block).div_ceil(blocks_per_group);
        if group_count != by_blocks {
            return Err(Error::corrupt(format!(
                "the inode count gives {group_count} block groups, the block count {by_blocks}"
            )));
        }
        if group_count.saturating_mul(desc_size) > image.size() {
            return Err(Error::corrupt(format!("{group_count} block groups do not fit in the image")));
        }

        // Descriptors fill whole blocks. Before `s_first_meta_bg` they follow the superblock
        // contiguously; from there on each meta group of `per_block` groups keeps its own
        // descriptor block at the start of its first group, after any superblock backup.
        let ro_compat = le32(&sb, 0x64);
        let trust_unused = ro_compat & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM) != 0;
        let per_block = block_size / desc_size;
        let first_meta_bg = if incompat & INCOMPAT_META_BG != 0 { u64::from(le32(&sb, 0x104)) } else { u64::MAX };
        let table_cap = (TABLE_READ_MAX / inode_size) as u32;
        let mut groups = Vec::with_capacity(group_count as usize);
        let mut buf = vec![0u8; block_size as usize];
        for b in 0..group_count.div_ceil(per_block) {
            let location = if b < first_meta_bg {
                Some(first_data_block + 1 + b)
            } else {
                let first = b * per_block;
                first
                    .checked_mul(blocks_per_group)
                    .and_then(|s| s.checked_add(first_data_block + u64::from(has_superblock(first, &sb))))
            };
            let offset = location.and_then(|l| l.checked_mul(block_size));
            let offset = offset.ok_or_else(|| Error::corrupt("group descriptor block out of range"))?;
            image.read_at(offset, &mut buf)?;
            for d in buf.chunks_exact(desc_size as usize).take((group_count - b * per_block) as usize) {
                let mut inode_table = u64::from(le32(d, 0x8));
                let mut unused = u32::from(le16(d, 0x1C));
                if desc_size >= 64 {
                    inode_table |= u64::from(le32(d, 0x28)) << 32;
                    unused |= u32::from(le16(d, 0x32)) << 16;
                }
                let used = match trust_unused {
                    true if le16(d, 0x12) & BG_INODE_UNINIT != 0 => 0,
                    true => inodes_per_group.saturating_sub(unused),
                    false => inodes_per_group,
                };
                groups.push(Group { inode_table, cached: used.min(table_cap) });
            }
        }
        Ok(Ext4 {
            image,
            block_size,
            blocks_count,
            inode_size,
            inodes_per_group,
            inodes_count,
            incompat,
            huge_file: ro_compat & RO_COMPAT_HUGE_FILE != 0,
            groups,
            tables: Mutex::new(TableCache::default()),
        })
    }

    /// Reads `buf.len()` bytes starting `within` bytes into the `count` blocks at `block`.
    fn read_blocks(&self, block: u64, count: u64, within: u64, buf: &mut [u8]) -> Result<()> {
        if block.checked_add(count).is_none_or(|end| end > self.blocks_count) {
            return Err(Error::corrupt(format!("block {block} is past the end of the volume")));
        }
        let offset = block.checked_mul(self.block_size).and_then(|o| o.checked_add(within));
        let offset = offset.ok_or_else(|| Error::corrupt("block address overflows"))?;
        Ok(self.image.read_at(offset, buf)?)
    }

    /// The cached start of a group's inode table (empty when it cannot be read).
    fn table(&self, g: usize) -> Arc<[u8]> {
        let mut cache = self.tables.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(t) = cache.map.get(&g) {
            return t.clone();
        }
        let len = self.groups[g].cached as usize * self.inode_size;
        let mut data = vec![0u8; len];
        let read = self.read_blocks(self.groups[g].inode_table, (len as u64).div_ceil(self.block_size), 0, &mut data);
        let data: Arc<[u8]> = if read.is_ok() { data.into() } else { Arc::from(Vec::new()) };
        cache.bytes += data.len();
        cache.map.insert(g, data.clone());
        cache.order.push_back(g);
        while cache.bytes > TABLE_CACHE_BYTES && cache.order.len() > 1 {
            if let Some(old) = cache.order.pop_front() {
                let freed = cache.map.remove(&old).map_or(0, |t| t.len());
                cache.bytes -= freed;
            }
        }
        data
    }

    /// Runs `f` on the raw bytes of inode `ino`.
    fn with_raw<T>(&self, ino: u32, f: impl FnOnce(&[u8]) -> T) -> Result<T> {
        if ino == 0 || ino > self.inodes_count {
            return Err(Error::corrupt(format!("inode {ino} out of range")));
        }
        let g = ((ino - 1) / self.inodes_per_group) as usize;
        let index = (ino - 1) % self.inodes_per_group;
        let group = self.groups.get(g).ok_or_else(|| Error::corrupt(format!("inode {ino} has no group")))?;
        let start = index as usize * self.inode_size;
        if index < group.cached {
            let table = self.table(g);
            if let Some(raw) = table.get(start..start + self.inode_size) {
                return Ok(f(raw));
            }
        }
        let mut raw = vec![0u8; self.inode_size];
        self.read_blocks(
            group.inode_table,
            ((start + self.inode_size) as u64).div_ceil(self.block_size),
            start as u64,
            &mut raw,
        )?;
        Ok(f(&raw))
    }

    fn inode(&self, ino: u32) -> Result<Inode> {
        self.with_raw(ino, |raw| Inode::parse(raw, self))
    }

    /// Inline data: the 60 bytes of `i_block` followed by the `system.data` attribute value.
    fn inline_data(&self, ino: u32) -> Result<Vec<u8>> {
        self.with_raw(ino, |raw| {
            let mut out = raw[0x28..0x64].to_vec();
            let start = 128 + usize::from(le16(raw, 0x80));
            if raw.len() <= 128 || le32(raw, start) != XATTR_MAGIC {
                return Ok(out);
            }
            // Entries follow the 4-byte header; value offsets count from the first entry.
            let base = start + 4;
            let mut off = base;
            while off + 16 <= raw.len() && le32(raw, off) != 0 {
                let name_len = usize::from(raw[off]);
                let name = raw.get(off + 16..off + 16 + name_len);
                if raw[off + 1] == XATTR_INDEX_SYSTEM && name == Some(b"data") {
                    if le32(raw, off + 4) != 0 {
                        return Err(Error::unsupported("inline data stored in an attribute inode"));
                    }
                    let value_start = base + usize::from(le16(raw, off + 2));
                    let value = raw.get(value_start..value_start.saturating_add(le32(raw, off + 8) as usize));
                    out.extend_from_slice(value.ok_or_else(|| Error::corrupt("inline data out of the inode"))?);
                    break;
                }
                off += (16 + name_len + 3) & !3;
            }
            Ok(out)
        })?
    }

    /// Maps logical block `lblk` through an extent tree rooted in `root`.
    fn map_extents(&self, root: &[u8; 60], lblk: u64, cache: &mut Blocks) -> Result<Run> {
        let hole = |end: u64| Run { phys: None, len: end.saturating_sub(lblk).max(1) };
        let mut node: Option<u64> = None;
        let mut limit = 1u64 << 32;
        let mut expected_depth = None;
        for _ in 0..=EXTENT_MAX_DEPTH {
            let data: &[u8] = match node {
                None => root,
                Some(block) => cache.get(self, block)?,
            };
            let depth = le16(data, 6);
            if le16(data, 0) != EXTENT_MAGIC || depth > EXTENT_MAX_DEPTH || expected_depth.is_some_and(|d| d != depth) {
                return Err(Error::corrupt("bad extent tree node"));
            }
            let entries = usize::from(le16(data, 2)).min((data.len() - 12) / 12);
            let entry = |i: usize| &data[12 + 12 * i..24 + 12 * i];
            if depth == 0 {
                for i in 0..entries {
                    let e = entry(i);
                    let first = u64::from(le32(e, 0));
                    let (len, unwritten) = match le16(e, 4) {
                        l if l > 32768 => (u64::from(l - 32768), true),
                        l => (u64::from(l), false),
                    };
                    if lblk < first {
                        return Ok(hole(first.min(limit)));
                    }
                    if lblk < first + len {
                        let start = u64::from(le32(e, 8)) | u64::from(le16(e, 6)) << 32;
                        let phys = (!unwritten).then_some(start + (lblk - first));
                        return Ok(Run { phys, len: first + len - lblk });
                    }
                }
                return Ok(hole(limit));
            }
            let Some(i) = (0..entries).rev().find(|&i| u64::from(le32(entry(i), 0)) <= lblk) else {
                return Ok(hole(if entries > 0 { u64::from(le32(entry(0), 0)).min(limit) } else { limit }));
            };
            if i + 1 < entries {
                limit = limit.min(u64::from(le32(entry(i + 1), 0)));
            }
            let e = entry(i);
            node = Some(u64::from(le32(e, 4)) | u64::from(le16(e, 8)) << 32);
            expected_depth = Some(depth - 1);
        }
        Err(Error::corrupt("extent tree too deep"))
    }

    /// Maps logical block `lblk` through ext2/ext3 direct and indirect block pointers.
    fn map_blocks(&self, iblock: &[u8; 60], lblk: u64, cache: &mut Blocks) -> Result<Run> {
        let per = self.block_size / 4;
        // A run of equal-or-consecutive pointers starting at `i` in `ptrs` (`count` pointers).
        let run = |ptrs: &[u8], i: u64, count: u64| {
            let phys = u64::from(le32(ptrs, i as usize * 4));
            let mut len = 1;
            while i + len < count {
                let next = u64::from(le32(ptrs, (i + len) as usize * 4));
                if (phys == 0 && next != 0) || (phys != 0 && next != phys + len) {
                    break;
                }
                len += 1;
            }
            Run { phys: (phys != 0).then_some(phys), len }
        };
        if lblk < 12 {
            return Ok(run(iblock, lblk, 12));
        }
        let mut rel = lblk - 12;
        let mut span = per;
        let mut slot = 12;
        while rel >= span {
            rel -= span;
            span *= per;
            slot += 1;
            if slot > 14 {
                return Ok(Run { phys: None, len: u64::MAX / 2 });
            }
        }
        let mut block = u64::from(le32(iblock, slot * 4));
        loop {
            if block == 0 {
                return Ok(Run { phys: None, len: span - rel });
            }
            span /= per;
            let index = rel / span;
            rel %= span;
            let data = cache.get(self, block)?;
            if span == 1 {
                return Ok(run(data, index, per));
            }
            block = u64::from(le32(data, index as usize * 4));
        }
    }

    /// Maps logical block `lblk` of `inode` through its extent tree or block map.
    fn map(&self, inode: &Inode, lblk: u64, cache: &mut Blocks) -> Result<Run> {
        match inode.flags & FL_EXTENTS != 0 {
            true if lblk >= 1 << 32 => Ok(Run { phys: None, len: u64::MAX / 2 }),
            true => self.map_extents(&inode.block, lblk, cache),
            false => self.map_blocks(&inode.block, lblk, cache),
        }
    }

    /// Reads file content of an already-parsed inode.
    fn read_inode(&self, ino: u32, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if inode.flags & FL_ENCRYPT != 0 {
            return Err(Error::unsupported(format!("inode {ino} is encrypted")));
        }
        if offset >= inode.size {
            return Ok(0);
        }
        let n = (inode.size - offset).min(buf.len() as u64) as usize;
        let buf = &mut buf[..n];
        let from_bytes = |data: &[u8], buf: &mut [u8]| {
            let have = data.get(offset as usize..).unwrap_or(&[]);
            let k = have.len().min(buf.len());
            buf[..k].copy_from_slice(&have[..k]);
            buf[k..].fill(0);
        };
        if inode.flags & FL_INLINE_DATA != 0 {
            from_bytes(&self.inline_data(ino)?, buf);
            return Ok(n);
        }
        let extents = inode.flags & FL_EXTENTS != 0;
        let acl_blocks = if inode.file_acl != 0 { self.block_size / 512 } else { 0 };
        if !extents && inode.kind() == Kind::Symlink && inode.size < 60 && u64::from(inode.blocks_lo) <= acl_blocks {
            from_bytes(&inode.block, buf);
            return Ok(n);
        }
        let bs = self.block_size;
        let mut cache = Blocks::new();
        let mut done = 0;
        while done < n {
            let pos = offset + done as u64;
            let (lblk, within) = (pos / bs, pos % bs);
            let run = self.map(inode, lblk, &mut cache)?;
            let take = run.len.saturating_mul(bs).saturating_sub(within).min((n - done) as u64) as usize;
            let out = &mut buf[done..done + take];
            match run.phys {
                None => out.fill(0),
                Some(block) => {
                    self.read_blocks(block, run.len.min((within + take as u64).div_ceil(bs)), within, out)?
                }
            }
            done += take;
        }
        Ok(n)
    }

    fn symlink_target(&self, ino: u32, inode: &Inode) -> Result<String> {
        if inode.size > MAX_PATH as u64 {
            return Err(Error::corrupt(format!("symlink of {} bytes", inode.size)));
        }
        let mut buf = vec![0u8; inode.size as usize];
        let n = self.read_inode(ino, inode, 0, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// Calls `f(inode, name)` for each live entry in one directory block (or inline region),
    /// skipping `.` and `..`. Returns false when the block is damaged.
    fn scan_block(&self, block: &[u8], f: &mut dyn FnMut(u32, &[u8])) -> bool {
        let filetype = self.incompat & INCOMPAT_FILETYPE != 0;
        let mut off = 0;
        while off + 8 <= block.len() {
            let ino = le32(block, off);
            let mut rec_len = usize::from(le16(block, off + 4));
            if self.block_size >= 65536 && (rec_len == 0 || rec_len == 65535) && off == 0 {
                rec_len = 65536;
            }
            let name_len = if filetype { usize::from(block[off + 6]) } else { usize::from(le16(block, off + 6)) };
            if rec_len < 8
                || rec_len % 4 != 0
                || off + rec_len > block.len()
                || 8 + name_len > rec_len
                || name_len > 255
            {
                return false;
            }
            let name = &block[off + 8..off + 8 + name_len];
            if ino != 0 && name != b"." && name != b".." {
                f(ino, name);
            }
            off += rec_len;
        }
        true
    }
}

/// The state of one walk: the directory blocks already read, and reusable buffers.
struct Walk<'w, R> {
    fs: &'w Ext4<R>,
    seen: HashSet<u64>,
    block: Vec<u8>,
    cache: Blocks,
}

impl<R: ReadAt> Tree for Walk<'_, R> {
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let fs = self.fs;
        let ino = u32::try_from(dir).map_err(|_| Error::corrupt(format!("inode {dir} out of range")))?;
        let inode = fs.inode(ino)?;
        if inode.flags & FL_ENCRYPT != 0 {
            return Err(Error::unsupported("encrypted directory"));
        }
        let full = Cell::new(false);
        let mut push = |ino: u32, name: &[u8]| {
            if !out.push(u64::from(ino), name) {
                full.set(true);
            }
        };
        let damaged = |i: u64| format!("{}: damaged directory block {i}, rest of block skipped", shown(path));
        if inode.flags & FL_INLINE_DATA != 0 {
            // Inline directories start with the parent's inode number instead of `.` and `..`.
            let mut content = fs.inline_data(ino)?;
            content.truncate((inode.size as usize).max(60));
            for (i, region) in [&content[4..60], &content[60..]].into_iter().enumerate() {
                if !fs.scan_block(region, &mut push) {
                    warn(damaged(i as u64));
                }
            }
            return Ok(());
        }
        let bs = fs.block_size;
        let blocks = inode.size.div_ceil(bs);
        let mut lblk = 0;
        while lblk < blocks && !full.get() {
            let run = fs.map(&inode, lblk, &mut self.cache)?;
            let len = run.len.min(blocks - lblk);
            for i in 0..len {
                let Some(phys) = run.phys.map(|p| p + i) else { break };
                if !self.seen.insert(phys) {
                    warn(format!(
                        "{}: directory block {} was already read for another directory; rest skipped",
                        shown(path),
                        lblk + i
                    ));
                    return Ok(());
                }
                let n = bs.min(inode.size - (lblk + i) * bs) as usize;
                self.block.resize(n, 0);
                fs.read_blocks(phys, 1, 0, &mut self.block)?;
                if !fs.scan_block(&self.block, &mut push) {
                    warn(damaged(lblk + i));
                }
                if full.get() {
                    break;
                }
            }
            lblk += len;
        }
        Ok(())
    }

    fn node(&mut self, ino: u64, path: &str, warn: &mut dyn FnMut(String)) -> Result<Node> {
        let fs = self.fs;
        let ino = u32::try_from(ino).map_err(|_| Error::corrupt(format!("inode {ino} out of range")))?;
        let inode = fs.inode(ino)?;
        if inode.mode == 0 {
            return Err(Error::corrupt(format!("entry points to unused inode {ino}")));
        }
        let kind = inode.kind();
        let mut link_target = None;
        if kind == Kind::Symlink {
            match fs.symlink_target(ino, &inode) {
                Ok(target) => link_target = Some(target),
                Err(e) => warn(format!("{}: symlink target: {e}", shown(path))),
            }
        }
        Ok(Node {
            path: String::new(),
            inode: u64::from(ino),
            kind,
            mode: u32::from(inode.mode),
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            allocated: inode.allocated,
            links: u32::from(inode.links),
            accessed: inode.accessed,
            modified: inode.modified,
            changed: inode.changed,
            created: inode.created,
            link_target,
        })
    }
}

impl<R: ReadAt> Volume for Ext4<R> {
    fn kind(&self) -> &'static str {
        "ext4"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        const ROOT: u32 = 2;
        if self.inode(ROOT)?.kind() != Kind::Directory {
            return Err(Error::corrupt("root inode is not a directory"));
        }
        let mut walk = Walk { fs: self, seen: HashSet::new(), block: Vec::new(), cache: Blocks::new() };
        walk_tree("ext4", &mut walk, u64::from(ROOT), visit, warn)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let ino = u32::try_from(inode).map_err(|_| Error::corrupt(format!("inode {inode} out of range")))?;
        let parsed = self.inode(ino)?;
        if parsed.kind() == Kind::Other {
            return Err(Error::unsupported(format!("inode {ino} is not a file, directory or symlink")));
        }
        self.read_inode(ino, &parsed, offset, buf)
    }
}

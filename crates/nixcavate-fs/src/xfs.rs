//! XFS, read-only.
//!
//! Written from "XFS Algorithms & Data Structures" (the xfs-documentation project's on-disk
//! format guide). Every on-disk integer is big-endian.
//!
//! Supported:
//! - v4 and v5 (CRC) superblocks and their allocation-group geometry;
//! - inodes read directly by number (AG, AG block and offset decoded with the superblock's
//!   log2 fields); the inode B+trees are not needed for a walk from the root and are not read;
//! - v1, v2 and v3 inode cores, with the v3 creation time, bigtime timestamps and large
//!   extent counts (nrext64);
//! - data forks in local, extents and B+tree (bmbt) format; holes and unwritten extents read
//!   as zeros. A bmbt is read until it holds more records than the inode's extent count, and a
//!   bmbt block reached twice is damage;
//! - shortform, block, leaf and node directories. Of the multi-block forms only the data
//!   blocks are read (directory offsets below 32 GiB): the leaf, node and free-index blocks
//!   only speed up lookups and are not needed to list entries. A walk reads each directory
//!   block once: a directory whose map names a block already read is listed up to there;
//! - local and remote symlinks (local or extents format), including the v5 per-block remote
//!   symlink header.
//!
//! Not supported: files on the realtime device (listed, but `read` refuses them), the log (a
//! dirty log is not replayed; the reader sees what is on disk), quota, extended attributes
//! (and so parent pointers), v1 directories, and checksum verification. Inodes that no
//! directory reaches (orphans) are not listed. Reflink and the reverse-mapping B+tree do not
//! affect reading.

use std::collections::HashSet;

use crate::{be16, be32, be64, shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Tree, Volume};

mod dir;

use dir::{parse_data_block, parse_shortform};

/// Directory byte offset where the leaf blocks start; data blocks lie below it.
const DIR_LEAF_OFFSET: u64 = 1 << 35;
/// Longest symlink target the format allows.
const MAX_SYMLINK: u64 = 1024;
/// Deepest bmbt the format can build (the root in the inode plus interior levels).
const MAX_BMBT_LEVEL: u16 = 9;
/// Extent records accepted for one fork.
const MAX_EXTENTS: usize = 1 << 22;

const FMT_DEV: u8 = 0;
const FMT_LOCAL: u8 = 1;
const FMT_EXTENTS: u8 = 2;
const FMT_BTREE: u8 = 3;

const DIFLAG_REALTIME: u16 = 0x1;
const DIFLAG2_BIGTIME: u64 = 0x8;
const DIFLAG2_NREXT64: u64 = 0x10;

/// Incompatible v5 features this reader knows about (ftype, sparse inodes, meta uuid,
/// bigtime, needsrepair, nrext64, exchange-range, parent pointers, metadir). None of them
/// changes how the structures read here are laid out beyond what is handled.
const KNOWN_INCOMPAT: u32 = 0x1ff;

/// What the superblock says about the layout.
struct Geometry {
    block_log: u32,
    block_size: u64,
    ag_blocks: u64,
    ag_count: u64,
    ag_blk_log: u32,
    inode_size: usize,
    inode_log: u32,
    inop_blog: u32,
    dir_blk_size: usize,
    root: u64,
    v5: bool,
    ftype: bool,
}

fn parse_superblock(sb: &[u8]) -> Result<Geometry> {
    if sb.get(0..4) != Some(b"XFSB".as_slice()) {
        return Err(Error::corrupt("no XFS superblock magic"));
    }
    let versionnum = be16(sb, 100);
    let v5 = match versionnum & 0xf {
        4 => false,
        5 => true,
        1..=3 => return Err(Error::unsupported(format!("XFS version {}", versionnum & 0xf))),
        v => return Err(Error::corrupt(format!("XFS version {v}"))),
    };
    let byte = |at: usize| u32::from(sb.get(at).copied().unwrap_or(0));
    let block_size = be32(sb, 4);
    let block_log = byte(120);
    if !(9..=16).contains(&block_log) || block_size != 1 << block_log {
        return Err(Error::corrupt(format!("block size {block_size}")));
    }
    let inode_size = u32::from(be16(sb, 104));
    let inode_log = byte(122);
    if !(8..=11).contains(&inode_log) || inode_size != 1 << inode_log || inode_log > block_log {
        return Err(Error::corrupt(format!("inode size {inode_size}")));
    }
    let inop_blog = byte(123);
    if inop_blog != block_log - inode_log || u32::from(be16(sb, 106)) != 1 << inop_blog {
        return Err(Error::corrupt("inodes per block"));
    }
    let ag_blocks = be32(sb, 84);
    let ag_blk_log = byte(124);
    let ag_count = be32(sb, 88);
    if ag_blocks == 0 || ag_blk_log > 31 || u64::from(ag_blocks) > 1 << ag_blk_log || ag_count == 0 {
        return Err(Error::corrupt("allocation group geometry"));
    }
    if ag_blk_log + inop_blog > 56 {
        return Err(Error::corrupt("inode number layout"));
    }
    let dir_blk_size = (block_size as usize) << byte(192).min(16);
    if dir_blk_size > 65536 {
        return Err(Error::corrupt("directory block size"));
    }
    let ftype = if v5 {
        let incompat = be32(sb, 216);
        if incompat & !KNOWN_INCOMPAT != 0 {
            return Err(Error::unsupported(format!("incompatible features {incompat:#x}")));
        }
        if inode_size < 512 {
            return Err(Error::corrupt("v5 inodes smaller than 512 bytes"));
        }
        incompat & 0x1 != 0
    } else {
        if versionnum & 0x2000 == 0 {
            return Err(Error::unsupported("v1 directories"));
        }
        versionnum & 0x8000 != 0 && be32(sb, 200) & 0x200 != 0
    };
    Ok(Geometry {
        block_log,
        block_size: u64::from(block_size),
        ag_blocks: u64::from(ag_blocks),
        ag_count: u64::from(ag_count),
        ag_blk_log,
        inode_size: inode_size as usize,
        inode_log,
        inop_blog,
        dir_blk_size,
        root: be64(sb, 56),
        v5,
        ftype,
    })
}

/// Recognizes an XFS superblock at the start of `image`.
pub fn probe(image: &dyn ReadAt) -> bool {
    let mut sb = [0u8; 512];
    image.read_at(0, &mut sb).is_ok() && parse_superblock(&sb).is_ok()
}

/// One extent record: `len` blocks of the file from block `off` are at filesystem block
/// `block`, or are allocated but unwritten.
#[derive(Clone, Copy, Debug)]
struct Extent {
    off: u64,
    block: u64,
    len: u64,
    unwritten: bool,
}

/// Unpacks a 128-bit extent record: flag (1 bit), startoff (54), startblock (52), blockcount (21).
fn decode_extent(rec: &[u8]) -> Extent {
    let l0 = be64(rec, 0);
    let l1 = be64(rec, 8);
    Extent {
        off: (l0 >> 9) & ((1 << 54) - 1),
        block: ((l0 & 0x1ff) << 43) | (l1 >> 21),
        len: l1 & ((1 << 21) - 1),
        unwritten: l0 >> 63 == 1,
    }
}

/// The fields of an inode core the reader uses. The data fork stays in the raw inode buffer.
#[derive(Clone, Copy, Debug)]
struct Core {
    mode: u16,
    format: u8,
    flags: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    nextents: u64,
    /// `di_nblocks`: blocks of data and of the bmbt that maps it.
    nblocks: u64,
    atime: Option<i64>,
    mtime: Option<i64>,
    ctime: Option<i64>,
    crtime: Option<i64>,
    fork_start: usize,
    fork_len: usize,
}

impl Core {
    fn kind(&self) -> Kind {
        match self.mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Directory,
            0o120000 => Kind::Symlink,
            _ => Kind::Other,
        }
    }

    fn fork<'r>(&self, raw: &'r [u8]) -> &'r [u8] {
        raw.get(self.fork_start..self.fork_start + self.fork_len).unwrap_or(&[])
    }
}

/// Legacy timestamps are signed seconds and nanoseconds; bigtime ones count nanoseconds from
/// 2^31 seconds before the Unix epoch.
fn timestamp(raw: &[u8], at: usize, bigtime: bool) -> Option<i64> {
    let ns = if bigtime {
        let t = be64(raw, at);
        if t == 0 {
            return None;
        }
        i128::from(t) - (1i128 << 31) * 1_000_000_000
    } else {
        let sec = be32(raw, at) as i32;
        let nsec = be32(raw, at + 4) as i32;
        if sec == 0 && nsec == 0 {
            return None;
        }
        i128::from(sec) * 1_000_000_000 + i128::from(nsec)
    };
    i64::try_from(ns).ok()
}

/// An opened XFS filesystem.
pub struct Xfs<R> {
    image: R,
    g: Geometry,
}

impl<R: ReadAt> Xfs<R> {
    pub fn open(image: R) -> Result<Xfs<R>> {
        let mut sb = [0u8; 512];
        image.read_at(0, &mut sb)?;
        let fs = Xfs { image, g: parse_superblock(&sb)? };
        let mut raw = Vec::new();
        let root = fs.read_inode(fs.g.root, &mut raw)?;
        if root.kind() != Kind::Directory {
            return Err(Error::corrupt("root inode is not a directory"));
        }
        Ok(fs)
    }

    /// Byte offset of an inode: AG number, AG block and slot packed into the inode number.
    fn inode_pos(&self, ino: u64) -> Option<u64> {
        let g = &self.g;
        let slot = ino & ((1 << g.inop_blog) - 1);
        let agbno = (ino >> g.inop_blog) & ((1 << g.ag_blk_log) - 1);
        let agno = ino >> (g.inop_blog + g.ag_blk_log);
        if agno >= g.ag_count || agbno >= g.ag_blocks {
            return None;
        }
        (agno * g.ag_blocks + agbno).checked_mul(g.block_size)?.checked_add(slot << g.inode_log)
    }

    /// Byte offset of a run of `len` filesystem blocks (AG number and AG block packed into
    /// `fsb`), refusing runs that leave their allocation group.
    fn run_pos(&self, fsb: u64, len: u64) -> Option<u64> {
        let g = &self.g;
        let agno = fsb >> g.ag_blk_log;
        let agbno = fsb & ((1 << g.ag_blk_log) - 1);
        if agno >= g.ag_count || agbno.checked_add(len)? > g.ag_blocks {
            return None;
        }
        (agno * g.ag_blocks + agbno).checked_mul(g.block_size)
    }

    fn parse_inode(&self, ino: u64, raw: &[u8]) -> Result<Core> {
        if be16(raw, 0) != 0x494e {
            return Err(Error::corrupt(format!("inode {ino}: bad magic")));
        }
        let version = raw.get(4).copied().unwrap_or(0);
        let core_size = match version {
            1 | 2 => 100,
            3 if self.g.v5 => 176,
            _ => return Err(Error::corrupt(format!("inode {ino}: version {version}"))),
        };
        if version == 3 && be64(raw, 152) != ino {
            return Err(Error::corrupt(format!("inode {ino}: records number {}", be64(raw, 152))));
        }
        let flags2 = if version == 3 { be64(raw, 120) } else { 0 };
        let bigtime = flags2 & DIFLAG2_BIGTIME != 0;
        let literal = self.g.inode_size - core_size;
        let fork_off = usize::from(raw.get(82).copied().unwrap_or(0)) * 8;
        let fork_len = match fork_off {
            0 => literal,
            n if n <= literal => n,
            _ => return Err(Error::corrupt(format!("inode {ino}: fork offset {fork_off}"))),
        };
        Ok(Core {
            mode: be16(raw, 2),
            format: raw.get(5).copied().unwrap_or(0),
            flags: be16(raw, 90),
            uid: be32(raw, 8),
            gid: be32(raw, 12),
            nlink: if version == 1 { u32::from(be16(raw, 6)) } else { be32(raw, 16) },
            size: be64(raw, 56),
            nextents: if flags2 & DIFLAG2_NREXT64 != 0 { be64(raw, 24) } else { u64::from(be32(raw, 76)) },
            nblocks: be64(raw, 64),
            atime: timestamp(raw, 32, bigtime),
            mtime: timestamp(raw, 40, bigtime),
            ctime: timestamp(raw, 48, bigtime),
            crtime: if version == 3 { timestamp(raw, 144, bigtime) } else { None },
            fork_start: core_size,
            fork_len,
        })
    }

    /// Reads one inode into `raw` without caching.
    fn read_inode(&self, ino: u64, raw: &mut Vec<u8>) -> Result<Core> {
        let pos = self.inode_pos(ino).ok_or_else(|| Error::corrupt(format!("inode {ino} out of range")))?;
        raw.resize(self.g.inode_size, 0);
        self.image.read_at(pos, raw)?;
        self.parse_inode(ino, raw)
    }

    /// The extent list of an extents- or btree-format data fork, sorted by file offset.
    fn extents(&self, core: &Core, raw: &[u8], out: &mut Vec<Extent>, scratch: &mut Vec<u8>) -> Result<()> {
        out.clear();
        let fork = core.fork(raw);
        match core.format {
            FMT_EXTENTS => {
                let n = usize::try_from(core.nextents).unwrap_or(usize::MAX);
                if n > fork.len() / 16 {
                    return Err(Error::corrupt(format!("{n} extents do not fit the inode")));
                }
                out.extend(fork.chunks_exact(16).take(n).map(decode_extent));
            }
            FMT_BTREE => {
                // The root (bmdr) block: level, record count, keys, then pointers placed after
                // as many keys as the fork could hold.
                let level = be16(fork, 0);
                let numrecs = usize::from(be16(fork, 2));
                let maxrecs = fork.len().saturating_sub(4) / 16;
                if level == 0 || level > MAX_BMBT_LEVEL || numrecs == 0 || numrecs > maxrecs {
                    return Err(Error::corrupt("bmbt root"));
                }
                let mut seen = HashSet::new();
                for i in 0..numrecs {
                    let ptr = be64(fork, 4 + maxrecs * 8 + i * 8);
                    self.bmbt_node(ptr, level - 1, core.nextents, out, scratch, &mut seen)?;
                }
            }
            _ => {}
        }
        out.retain(|e| e.len > 0);
        out.sort_unstable_by_key(|e| e.off);
        Ok(())
    }

    /// Appends the records under bmbt block `fsb`, refusing a block reached twice and more
    /// records than the inode's extent count `nextents`.
    fn bmbt_node(
        &self,
        fsb: u64,
        level: u16,
        nextents: u64,
        out: &mut Vec<Extent>,
        scratch: &mut Vec<u8>,
        seen: &mut HashSet<u64>,
    ) -> Result<()> {
        if !seen.insert(fsb) {
            return Err(Error::corrupt(format!("bmbt block {fsb} reached twice")));
        }
        let bs = self.g.block_size as usize;
        let pos = self.run_pos(fsb, 1).ok_or_else(|| Error::corrupt(format!("bmbt block {fsb} out of range")))?;
        scratch.resize(bs, 0);
        self.image.read_at(pos, scratch)?;
        let (magic, header) = if self.g.v5 { (b"BMA3", 72) } else { (b"BMAP", 24) };
        if scratch.get(0..4) != Some(magic.as_slice()) || be16(scratch, 4) != level {
            return Err(Error::corrupt(format!("bmbt block {fsb}: bad magic or level")));
        }
        let numrecs = usize::from(be16(scratch, 6));
        let maxrecs = (bs - header) / 16;
        if numrecs == 0 || numrecs > maxrecs {
            return Err(Error::corrupt(format!("bmbt block {fsb}: {numrecs} records")));
        }
        if level == 0 {
            if out.len() + numrecs > MAX_EXTENTS || (out.len() + numrecs) as u64 > nextents {
                return Err(Error::corrupt("bmbt holds more extents than the inode records"));
            }
            out.extend(scratch[header..header + numrecs * 16].chunks_exact(16).map(decode_extent));
            return Ok(());
        }
        let ptrs: Vec<u64> = (0..numrecs).map(|i| be64(scratch, header + maxrecs * 8 + i * 8)).collect();
        for ptr in ptrs {
            self.bmbt_node(ptr, level - 1, nextents, out, scratch, seen)?;
        }
        Ok(())
    }

    /// Fills `buf` with the bytes at `offset` of a fork mapped by `extents`: zeros in holes
    /// and unwritten extents.
    fn read_mapped(&self, extents: &[Extent], offset: u64, buf: &mut [u8]) -> Result<()> {
        buf.fill(0);
        let bs = self.g.block_size;
        let end = offset.saturating_add(buf.len() as u64);
        let first_block = offset >> self.g.block_log;
        let first = extents.partition_point(|e| e.off.saturating_add(e.len) <= first_block);
        for e in &extents[first..] {
            let Some(e_start) = e.off.checked_mul(bs) else { break };
            if e_start >= end {
                break;
            }
            if e.unwritten {
                continue;
            }
            let from = e_start.max(offset);
            let to = e_start.saturating_add(e.len * bs).min(end);
            if from >= to {
                continue;
            }
            let disk = self
                .run_pos(e.block, e.len)
                .ok_or_else(|| Error::corrupt(format!("extent at block {} out of range", e.block)))?;
            let dst = &mut buf[(from - offset) as usize..(to - offset) as usize];
            self.image.read_at(disk.saturating_add(from - e_start), dst)?;
        }
        Ok(())
    }

    fn symlink_target(
        &self,
        core: &Core,
        raw: &[u8],
        extents: &mut Vec<Extent>,
        scratch: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        if core.size > MAX_SYMLINK {
            return Err(Error::corrupt(format!("symlink of {} bytes", core.size)));
        }
        let size = core.size as usize;
        match core.format {
            FMT_LOCAL => {
                core.fork(raw).get(..size).map(<[u8]>::to_vec).ok_or_else(|| Error::corrupt("inline symlink too long"))
            }
            FMT_EXTENTS => {
                self.extents(core, raw, extents, scratch)?;
                let mut target = vec![0u8; size];
                if !self.g.v5 {
                    self.read_mapped(extents, 0, &mut target)?;
                    return Ok(target);
                }
                // v5: every block starts with a 56-byte header that says how many bytes follow.
                target.clear();
                let bs = self.g.block_size as usize;
                scratch.resize(bs, 0);
                let mut block = 0u64;
                while target.len() < size {
                    if block >= 4 {
                        return Err(Error::corrupt("remote symlink spans too many blocks"));
                    }
                    self.read_mapped(extents, block * self.g.block_size, scratch)?;
                    if scratch.get(0..4) != Some(b"XSLM".as_slice()) {
                        return Err(Error::corrupt("remote symlink block: bad magic"));
                    }
                    let take = (be32(scratch, 8) as usize).min(bs - 56).min(size - target.len());
                    if take == 0 {
                        return Err(Error::corrupt("remote symlink block is empty"));
                    }
                    target.extend_from_slice(&scratch[56..56 + take]);
                    block += 1;
                }
                Ok(target)
            }
            f => Err(Error::corrupt(format!("symlink in fork format {f}"))),
        }
    }
}

/// Per-walk state: an inode window, the directory blocks already read, and reusable buffers.
struct Walker<'w, R> {
    fs: &'w Xfs<R>,
    window: Vec<u8>,
    window_start: u64,
    raw: Vec<u8>,
    extents: Vec<Extent>,
    block: Vec<u8>,
    seen: HashSet<u64>,
}

impl<'w, R: ReadAt> Walker<'w, R> {
    fn new(fs: &'w Xfs<R>) -> Self {
        Walker {
            fs,
            window: Vec::new(),
            window_start: 0,
            raw: Vec::new(),
            extents: Vec::new(),
            block: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Reads an inode through a window the size of an inode cluster, so the inodes of one
    /// directory, usually allocated together, cost one read.
    fn load(&mut self, ino: u64) -> Result<Core> {
        let fs = self.fs;
        let size = fs.g.inode_size;
        let pos = fs.inode_pos(ino).ok_or_else(|| Error::corrupt(format!("inode {ino} out of range")))?;
        let hit = pos >= self.window_start && pos - self.window_start + size as u64 <= self.window.len() as u64;
        if !hit {
            let width = (32 * size as u64).max(fs.g.block_size);
            let start = pos / width * width;
            let len = width.min(fs.image.size().saturating_sub(start));
            self.window.resize(len as usize, 0);
            self.window_start = start;
            if len < pos - start + size as u64 || fs.image.read_at(start, &mut self.window).is_err() {
                self.window.clear();
                return fs.read_inode(ino, &mut self.raw);
            }
        }
        let at = (pos - self.window_start) as usize;
        self.raw.clear();
        self.raw.extend_from_slice(&self.window[at..at + size]);
        fs.parse_inode(ino, &self.raw)
    }
}

impl<R: ReadAt> Tree for Walker<'_, R> {
    /// A damaged block ends the listing with a warning; the entries found before it are kept.
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let core = self.load(dir)?;
        if core.kind() != Kind::Directory {
            return Err(Error::corrupt("not a directory"));
        }
        let Walker { fs, raw, extents, block, seen, .. } = self;
        let g = &fs.g;
        match core.format {
            FMT_LOCAL => {
                let data = core.fork(raw);
                let data = data.get(..core.size as usize).unwrap_or(data);
                parse_shortform(data, g.ftype, out)
            }
            FMT_EXTENTS | FMT_BTREE => {
                fs.extents(&core, raw, extents, block)?;
                let per_block = (g.dir_blk_size as u64) >> g.block_log;
                let leaf_block = DIR_LEAF_OFFSET >> g.block_log;
                let mut next = 0u64;
                for (i, e) in extents.iter().enumerate() {
                    if e.off >= leaf_block {
                        break;
                    }
                    let mut d = (e.off / per_block * per_block).max(next);
                    let end = (e.off + e.len).min(leaf_block);
                    while d < end {
                        // Where the directory block starts on disk (in this extent or an earlier one).
                        let start = match d >= e.off {
                            true => Some(e),
                            false => extents[..i].iter().rev().find(|x| x.off <= d && d < x.off + x.len),
                        };
                        if let Some(x) = start {
                            if !seen.insert(x.block + (d - x.off)) {
                                warn(format!(
                                    "{}: directory block {d} was already read for another directory; rest skipped",
                                    shown(path)
                                ));
                                return Ok(());
                            }
                        }
                        block.resize(g.dir_blk_size, 0);
                        fs.read_mapped(extents, d << g.block_log, block)?;
                        if let Err(err) = parse_data_block(block, g.v5, g.ftype, out) {
                            warn(format!("{}: directory block {d}: {err}", shown(path)));
                            return Ok(());
                        }
                        if out.full() {
                            return Ok(());
                        }
                        d += per_block;
                    }
                    next = d;
                }
                Ok(())
            }
            f => Err(Error::corrupt(format!("directory in fork format {f}"))),
        }
    }

    fn node(&mut self, ino: u64, _path: &str, _warn: &mut dyn FnMut(String)) -> Result<Node> {
        let core = self.load(ino)?;
        let kind = core.kind();
        let link_target = if kind == Kind::Symlink {
            let target = self.fs.symlink_target(&core, &self.raw, &mut self.extents, &mut self.block)?;
            Some(String::from_utf8_lossy(&target).into_owned())
        } else {
            None
        };
        Ok(Node {
            path: String::new(),
            inode: ino,
            kind,
            mode: u32::from(core.mode),
            uid: core.uid,
            gid: core.gid,
            size: core.size,
            allocated: core.nblocks.saturating_mul(self.fs.g.block_size),
            links: core.nlink,
            accessed: core.atime,
            modified: core.mtime,
            changed: core.ctime,
            created: core.crtime,
            link_target,
        })
    }
}

impl<R: ReadAt> Volume for Xfs<R> {
    fn kind(&self) -> &'static str {
        "xfs"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        walk_tree("xfs", &mut Walker::new(self), self.g.root, visit, warn)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut raw = Vec::new();
        let core = self.read_inode(inode, &mut raw)?;
        let mut extents = Vec::new();
        let mut scratch = Vec::new();
        let kind = core.kind();
        if kind == Kind::Other || core.format == FMT_DEV {
            return Err(Error::unsupported("device, socket or FIFO has no content"));
        }
        if core.flags & DIFLAG_REALTIME != 0 {
            return Err(Error::unsupported("file on the realtime device"));
        }
        if kind == Kind::Symlink {
            let target = self.symlink_target(&core, &raw, &mut extents, &mut scratch)?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(target.len());
            let n = buf.len().min(target.len() - start);
            buf[..n].copy_from_slice(&target[start..start + n]);
            return Ok(n);
        }
        if offset >= core.size {
            return Ok(0);
        }
        let n = buf.len().min(usize::try_from(core.size - offset).unwrap_or(usize::MAX));
        let buf = &mut buf[..n];
        match core.format {
            FMT_LOCAL => {
                let data = core.fork(&raw);
                let start = offset as usize;
                let src = data.get(start..start + n).ok_or_else(|| Error::corrupt("inline data shorter than size"))?;
                buf.copy_from_slice(src);
            }
            FMT_EXTENTS | FMT_BTREE => {
                self.extents(&core, &raw, &mut extents, &mut scratch)?;
                self.read_mapped(&extents, offset, buf)?;
            }
            f => return Err(Error::corrupt(format!("data fork format {f}"))),
        }
        Ok(n)
    }
}

//! APFS, written from Apple's "Apple File System Reference" (developer.apple.com).
//!
//! Supported: the container superblock (the newest valid copy in the checkpoint descriptor
//! area, Fletcher-64 checked), object maps, B-trees with fixed and variable entries (a scan
//! that reaches a node twice stops with an error), volume superblocks and their names, roles,
//! case sensitivity and encryption flag, snapshot listing (name, transaction id, creation
//! time; [`Apfs::snapshots`]), and the file-system tree of an unencrypted volume:
//! inodes, hashed and plain directory records, hard links, file extents (sparse ranges read as
//! zeros, cloned files through `private_id`), symlink targets (`com.apple.fs.symlink`), and
//! transparently compressed files (`com.apple.decmpfs`), which are listed with their
//! uncompressed size and readable when their data sits in the attribute: types 1 (stored),
//! 3 (zlib) and 9 (stored after a 0xcc marker).
//!
//! Not supported: encrypted volumes (listed, not opened), sealed system volumes, reading a
//! snapshot's tree (only the live tree is read), other decmpfs types (LZVN, LZFSE and every
//! resource-fork type: `read` returns `Unsupported`), non-contiguous checkpoint descriptor
//! areas (block 0 is used), the space manager and reaper (a reader needs neither), and Fusion
//! or multi-device containers.
//!
//! Directories are reported with size 0 (APFS stores no directory size) and with the link
//! count `stat(2)` shows on macOS: the entry count plus 2.

mod btree;
mod decmpfs;
mod records;

use std::cmp::Ordering;

use btree::{Cache, Ctx, Disk, Tree};
use records::{split_key, time, Inode, Xdata};

use crate::{le16, le32, le64, shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Volume};

const NX_MAGIC: &[u8; 4] = b"NXSB";
const APFS_MAGIC: &[u8; 4] = b"APSB";
const NX_MAX_FILE_SYSTEMS: usize = 100;
/// The descriptor area is a B-tree rather than a run of blocks.
const XP_DESC_NOT_CONTIGUOUS: u32 = 0x8000_0000;
const MAX_DESC_BLOCKS: u32 = 4096;

const APFS_FS_UNENCRYPTED: u64 = 0x1;
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x8;
const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x20;

const ROOT_DIR_INO_NUM: u64 = 2;
const SYMLINK_XATTR: &[u8] = b"com.apple.fs.symlink";
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
/// Largest extended attribute read whole (decmpfs headers with inline data are a few KiB).
const XATTR_MAX: u64 = 1 << 20;
const MAX_SNAPSHOTS: usize = 100_000;

/// True when the image starts with an APFS container superblock.
pub fn probe(image: &dyn ReadAt) -> bool {
    let mut magic = [0u8; 4];
    image.read_at(32, &mut magic).is_ok() && &magic == NX_MAGIC
}

/// A snapshot of a volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub name: String,
    /// The transaction the snapshot captured.
    pub xid: u64,
    pub created: Option<i64>,
}

/// One volume of a container, as listed by [`Apfs::volumes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Position in the container's volume array: the argument to [`Apfs::volume`].
    pub index: usize,
    pub name: String,
    /// `apfs_role` (see [`VolumeInfo::role_name`]).
    pub role: u16,
    pub encrypted: bool,
    pub case_sensitive: bool,
}

impl VolumeInfo {
    pub fn role_name(&self) -> &'static str {
        match self.role {
            0 => "none",
            0x1 => "system",
            0x2 => "user",
            0x4 => "recovery",
            0x8 => "vm",
            0x10 => "preboot",
            0x20 => "installer",
            0x40 => "data",
            0x80 => "baseband",
            0xc0 => "update",
            0x100 => "xart",
            0x140 => "hardware",
            0x180 => "backup",
            0x200 => "enterprise",
            0x280 => "prelogin",
            _ => "unknown",
        }
    }
}

/// An APFS container (one GPT partition).
pub struct Apfs<R> {
    image: R,
    bs: u64,
    blocks: u64,
    /// Root node of the container object map's B-tree, and the checkpoint's transaction.
    omap: u64,
    xid: u64,
    /// `nx_fs_oid`: virtual ids of the volume superblocks, 0 for an empty slot.
    fs: Vec<u64>,
}

impl<R: ReadAt> Apfs<R> {
    pub fn open(image: R) -> Result<Apfs<R>> {
        let (bs, blocks, (omap, xid, fs)) = {
            let img: &dyn ReadAt = &image;
            let mut head = [0u8; 4096];
            img.read_at(0, &mut head)?;
            if &head[32..36] != NX_MAGIC {
                return Err(Error::corrupt("no APFS container superblock"));
            }
            let bs = le32(&head, 36);
            if !(4096..=65536).contains(&bs) || !bs.is_power_of_two() {
                return Err(Error::corrupt(format!("block size {bs}")));
            }
            let bs = u64::from(bs);
            let blocks = le64(&head, 40).min(img.size() / bs);
            let disk = Disk { img, bs, blocks };

            // Candidates: block 0 and every superblock in the checkpoint descriptor area, newest
            // valid one first.
            let mut candidates = vec![disk.block(0)?];
            let desc_blocks = le32(&candidates[0], 104);
            let desc_base = le64(&candidates[0], 112);
            if desc_blocks & XP_DESC_NOT_CONTIGUOUS == 0 {
                for i in 0..desc_blocks.min(MAX_DESC_BLOCKS) {
                    let Some(Ok(block)) = desc_base.checked_add(u64::from(i)).map(|p| disk.block(p)) else { continue };
                    if btree::object_type(&block) == btree::OBJECT_TYPE_NX_SUPERBLOCK
                        && &block[32..36] == NX_MAGIC
                        && btree::checksum_ok(&block)
                    {
                        candidates.push(block);
                    }
                }
            }
            candidates.sort_by_key(|b| std::cmp::Reverse((btree::checksum_ok(b), le64(b, 16))));
            let mut found = Err(Error::corrupt("no usable container superblock"));
            for sb in &candidates {
                found = from_superblock(disk, sb);
                if found.is_ok() {
                    break;
                }
            }
            (bs, blocks, found?)
        };
        Ok(Apfs { image, bs, blocks, omap, xid, fs })
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx { disk: Disk { img: &self.image, bs: self.bs, blocks: self.blocks }, omap: Some(self.omap), xid: self.xid }
    }

    /// Every volume whose superblock can be read, including encrypted ones. Empty and
    /// unreadable slots are left out, so use [`VolumeInfo::index`], not the list position.
    pub fn volumes(&self) -> Vec<VolumeInfo> {
        let mut out = Vec::new();
        for index in 0..self.fs.len() {
            let Ok(sb) = self.superblock(index) else { continue };
            out.push(VolumeInfo {
                index,
                name: sb.name.clone(),
                role: sb.role,
                encrypted: sb.encrypted(),
                case_sensitive: sb.incompat & APFS_INCOMPAT_CASE_INSENSITIVE == 0,
            });
        }
        out
    }

    /// The snapshots of volume `index`.
    pub fn snapshots(&self, index: usize) -> Result<Vec<Snapshot>> {
        let sb = self.superblock(index)?;
        let mut out = Vec::new();
        if sb.snaps == 0 {
            return Ok(out);
        }
        let ctx = self.volume_ctx(&sb)?;
        let tree = Tree { root: sb.snaps, physical: sb.snaps_type & btree::OBJ_PHYSICAL != 0, kv: (0, 0) };
        ctx.scan(&mut Cache::new(), tree, &|_| Ordering::Greater, false, &mut |k, v| {
            out.extend(records::parse_snapshot(k, v));
            Ok(out.len() < MAX_SNAPSHOTS)
        })?;
        Ok(out)
    }

    /// Opens the live file-system tree of volume `index`.
    pub fn volume(&self, index: usize) -> Result<ApfsVolume<R>>
    where
        R: Clone,
    {
        let sb = self.superblock(index)?;
        if sb.encrypted() {
            return Err(Error::unsupported("encrypted volume"));
        }
        if sb.incompat & APFS_INCOMPAT_SEALED_VOLUME != 0 {
            return Err(Error::unsupported("sealed volume"));
        }
        let ctx = self.volume_ctx(&sb)?;
        let tree = Tree { root: sb.root, physical: sb.root_type & btree::OBJ_PHYSICAL != 0, kv: (0, 0) };
        ctx.check_root(&mut Cache::new(), tree)?;
        let hashed = sb.incompat & (APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0;
        let omap = ctx.omap.unwrap_or(0);
        Ok(ApfsVolume {
            image: self.image.clone(),
            bs: self.bs,
            blocks: self.blocks,
            omap,
            xid: self.xid,
            tree,
            hashed,
        })
    }

    fn superblock(&self, index: usize) -> Result<Superblock> {
        let oid =
            *self.fs.get(index).filter(|&&o| o != 0).ok_or_else(|| Error::corrupt(format!("no volume {index}")))?;
        let ctx = self.ctx();
        let paddr = ctx.translate(&mut Cache::new(), oid)?;
        let b = ctx.disk.object(paddr, btree::OBJECT_TYPE_FS)?;
        if &b[32..36] != APFS_MAGIC || le64(&b, 8) != oid {
            return Err(Error::corrupt(format!("volume {index} has no valid superblock")));
        }
        let name = &b[704..960];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        Ok(Superblock {
            name: String::from_utf8_lossy(name).into_owned(),
            role: le16(&b, 964),
            fs_flags: le64(&b, 264),
            incompat: le64(&b, 56),
            omap: le64(&b, 128),
            root: le64(&b, 136),
            root_type: le32(&b, 116),
            snaps: le64(&b, 152),
            snaps_type: le32(&b, 124),
        })
    }

    fn volume_ctx(&self, sb: &Superblock) -> Result<Ctx<'_>> {
        let ctx = self.ctx();
        Ok(Ctx { disk: ctx.disk, omap: Some(omap_root(ctx.disk, sb.omap)?), xid: self.xid })
    }
}

/// The container object map and volume slots of one container superblock: (omap root, xid,
/// `nx_fs_oid`).
fn from_superblock(disk: Disk, sb: &[u8]) -> Result<(u64, u64, Vec<u64>)> {
    if u64::from(le32(sb, 36)) != disk.bs {
        return Err(Error::corrupt("container superblocks disagree on the block size"));
    }
    let xid = le64(sb, 16);
    let omap = omap_root(disk, le64(sb, 160))?;
    let ctx = Ctx { disk, omap: Some(omap), xid };
    ctx.check_root(&mut Cache::new(), Tree { root: omap, physical: true, kv: (16, 16) })?;
    let count = (le32(sb, 180) as usize).min(NX_MAX_FILE_SYSTEMS);
    Ok((omap, xid, (0..count).map(|i| le64(sb, 184 + 8 * i)).collect()))
}

/// The B-tree root of the object map stored at `paddr` (`omap_phys_t`).
fn omap_root(disk: Disk, paddr: u64) -> Result<u64> {
    Ok(le64(&disk.object(paddr, btree::OBJECT_TYPE_OMAP)?, 48))
}

/// The `apfs_superblock_t` fields this reader uses.
struct Superblock {
    name: String,
    role: u16,
    fs_flags: u64,
    incompat: u64,
    omap: u64,
    root: u64,
    root_type: u32,
    snaps: u64,
    snaps_type: u32,
}

impl Superblock {
    fn encrypted(&self) -> bool {
        self.fs_flags & APFS_FS_UNENCRYPTED == 0
    }
}

/// Bytes held in an extended attribute or behind it in a data stream.
enum Stream {
    Inline(Vec<u8>),
    Extents { oid: u64, size: u64 },
}

impl Stream {
    fn new(x: Xdata) -> Stream {
        match x {
            Xdata::Embedded(d) => Stream::Inline(d.to_vec()),
            Xdata::Stream { oid, size } => Stream::Extents { oid, size },
        }
    }
}

/// An inode with the extended attributes a walk or a read needs.
struct Found {
    inode: Inode,
    symlink: Option<Stream>,
    decmpfs: Option<Stream>,
}

impl Found {
    fn compressed(&self) -> bool {
        self.inode.bsd_flags & decmpfs::UF_COMPRESSED != 0 && self.decmpfs.is_some()
    }
}

/// The live file-system tree of one unencrypted volume.
pub struct ApfsVolume<R> {
    image: R,
    bs: u64,
    blocks: u64,
    /// Root node of the volume object map's B-tree, and the checkpoint's transaction.
    omap: u64,
    xid: u64,
    tree: Tree,
    /// Directory records use `j_drec_hashed_key_t`.
    hashed: bool,
}

impl<R: ReadAt> ApfsVolume<R> {
    fn ctx(&self) -> Ctx<'_> {
        Ctx { disk: Disk { img: &self.image, bs: self.bs, blocks: self.blocks }, omap: Some(self.omap), xid: self.xid }
    }

    /// The inode record of `oid` and, for symlinks and compressed files, its attributes.
    fn lookup(&self, cache: &mut Cache, oid: u64) -> Result<Option<Found>> {
        let mut found: Option<Found> = None;
        let cmp = |k: &[u8]| records::fs_cmp(k, oid, records::APFS_TYPE_INODE);
        self.ctx().scan(cache, self.tree, &cmp, false, &mut |k, v| {
            let Some((o, ty)) = split_key(k) else { return Ok(true) };
            if o != oid || ty > records::APFS_TYPE_XATTR {
                return Ok(false);
            }
            match (&mut found, ty) {
                (None, records::APFS_TYPE_INODE) => {
                    let Some(inode) = records::parse_inode(v) else { return Ok(false) };
                    let wanted = inode.mode & S_IFMT == S_IFLNK || inode.bsd_flags & decmpfs::UF_COMPRESSED != 0;
                    found = Some(Found { inode, symlink: None, decmpfs: None });
                    Ok(wanted)
                }
                (Some(f), records::APFS_TYPE_XATTR) => {
                    match records::parse_xattr(k, v) {
                        Some((SYMLINK_XATTR, x)) => f.symlink = Some(Stream::new(x)),
                        Some((decmpfs::XATTR, x)) => f.decmpfs = Some(Stream::new(x)),
                        _ => {}
                    }
                    Ok(true)
                }
                _ => Ok(false),
            }
        })?;
        Ok(found)
    }

    /// Reads from a data stream: file extents of `oid`, holes as zeros.
    fn read_stream(&self, cache: &mut Cache, stream: &Stream, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (oid, size) = match stream {
            Stream::Inline(data) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
                let n = buf.len().min(data.len() - start);
                buf[..n].copy_from_slice(&data[start..start + n]);
                return Ok(n);
            }
            &Stream::Extents { oid, size } => (oid, size),
        };
        if offset >= size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - offset) as usize;
        let end = offset + n as u64;
        buf[..n].fill(0);
        let target = (oid, records::APFS_TYPE_FILE_EXTENT);
        // Order extent keys at or before `offset` first, so the scan starts at the extent
        // that contains it.
        let cmp = |k: &[u8]| match split_key(k) {
            Some(kt) if kt == target => {
                if k.len() < 16 || le64(k, 8) <= offset {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            Some(kt) => kt.cmp(&target),
            None => Ordering::Less,
        };
        let ctx = self.ctx();
        let disk = ctx.disk;
        ctx.scan(cache, self.tree, &cmp, true, &mut |k, v| {
            match split_key(k) {
                Some(kt) if kt < target => return Ok(true),
                Some(kt) if kt > target => return Ok(false),
                _ => {}
            }
            let Some((logical, len, block)) = records::parse_extent(k, v) else { return Ok(true) };
            if logical >= end {
                return Ok(false);
            }
            let (from, to) = (logical.max(offset), logical.saturating_add(len).min(end));
            if from >= to || block == 0 {
                return Ok(true);
            }
            let phys = block.checked_mul(disk.bs).and_then(|p| p.checked_add(from - logical));
            match phys {
                Some(p) if p.saturating_add(to - from) <= disk.blocks * disk.bs => {
                    disk.img.read_at(p, &mut buf[(from - offset) as usize..(to - offset) as usize])?;
                    Ok(true)
                }
                _ => Err(Error::corrupt(format!("extent of object {oid:#x} is past the end of the container"))),
            }
        })?;
        Ok(n)
    }

    /// A small stream read whole.
    fn small(&self, cache: &mut Cache, stream: &Stream) -> Result<Vec<u8>> {
        let size = match stream {
            Stream::Inline(d) => return Ok(d.clone()),
            Stream::Extents { size, .. } => *size,
        };
        if size > XATTR_MAX {
            return Err(Error::corrupt("extended attribute too large"));
        }
        let mut out = vec![0u8; size as usize];
        let n = self.read_stream(cache, stream, 0, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn node(&self, cache: &mut Cache, path: &str, oid: u64, found: &Found) -> Result<Node> {
        let ino = &found.inode;
        let kind = match ino.mode & S_IFMT {
            S_IFDIR => Kind::Directory,
            S_IFREG => Kind::File,
            S_IFLNK => Kind::Symlink,
            _ => Kind::Other,
        };
        let mut link_target = None;
        let size = match kind {
            Kind::Symlink => {
                let target = match &found.symlink {
                    Some(s) => self.small(cache, s)?,
                    None => return Err(Error::corrupt(format!("{path}: symlink without a target"))),
                };
                let target = target.strip_suffix(&[0]).unwrap_or(&target);
                link_target = Some(String::from_utf8_lossy(target).into_owned());
                target.len() as u64
            }
            Kind::File if found.compressed() => {
                let mut header = [0u8; 16];
                let x = found.decmpfs.as_ref().map_or(Ok(0), |s| self.read_stream(cache, s, 0, &mut header))?;
                decmpfs::header(&header[..x]).map_or(ino.size, |(_, size)| size)
            }
            Kind::File => ino.size,
            Kind::Directory | Kind::Other => 0,
        };
        let links = u32::try_from(ino.nlink).unwrap_or(0);
        Ok(Node {
            path: String::new(),
            inode: oid,
            kind,
            mode: u32::from(ino.mode),
            uid: ino.uid,
            gid: ino.gid,
            size,
            allocated: ino.alloced,
            // Directories record their entry count; report it as stat(2) does on macOS.
            links: if kind == Kind::Directory { links.saturating_add(2) } else { links },
            accessed: time(ino.accessed),
            modified: time(ino.modified),
            changed: time(ino.changed),
            created: time(ino.created),
            link_target,
        })
    }
}

/// The state of one walk: decoded nodes and the walk's work budget.
struct Walk<'w, R> {
    volume: &'w ApfsVolume<R>,
    cache: Cache,
}

impl<R: ReadAt> crate::Tree for Walk<'_, R> {
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let cmp = |k: &[u8]| records::fs_cmp(k, dir, records::APFS_TYPE_DIR_REC);
        let mut bad = 0usize;
        let listed = self.volume.ctx().scan(&mut self.cache, self.volume.tree, &cmp, false, &mut |k, v| {
            if split_key(k) != Some((dir, records::APFS_TYPE_DIR_REC)) {
                return Ok(false);
            }
            match records::parse_drec(k, v, self.volume.hashed) {
                Some((name, id)) => Ok(out.push(id, name)),
                None => {
                    bad += 1;
                    Ok(true)
                }
            }
        });
        if bad > 0 {
            warn(format!("{}: {bad} malformed directory records skipped", shown(path)));
        }
        listed
    }

    fn node(&mut self, ino: u64, path: &str, _warn: &mut dyn FnMut(String)) -> Result<Node> {
        match self.volume.lookup(&mut self.cache, ino)? {
            Some(found) => self.volume.node(&mut self.cache, path, ino, &found),
            None => Err(Error::corrupt(format!("inode {ino:#x} not found"))),
        }
    }

    fn exhausted(&self) -> bool {
        self.cache.exhausted()
    }
}

impl<R: ReadAt> Volume for ApfsVolume<R> {
    fn kind(&self) -> &'static str {
        "apfs"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        walk_tree("apfs", &mut Walk { volume: self, cache: Cache::new() }, ROOT_DIR_INO_NUM, visit, warn)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut cache = Cache::new();
        let found = self.lookup(&mut cache, inode)?.ok_or_else(|| Error::corrupt(format!("no inode {inode:#x}")))?;
        if found.inode.mode & S_IFMT != S_IFREG {
            return Err(Error::unsupported("not a regular file"));
        }
        if let (true, Some(x)) = (found.compressed(), &found.decmpfs) {
            return decmpfs::read(&self.small(&mut cache, x)?, offset, buf);
        }
        let ino = &found.inode;
        self.read_stream(&mut cache, &Stream::Extents { oid: ino.private_id, size: ino.size }, offset, buf)
    }
}

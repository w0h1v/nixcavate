//! UFS1 and UFS2 (the Berkeley Fast File System), read-only.
//!
//! Written from FreeBSD's `sys/ufs/ffs/fs.h` (superblock, cylinder group), `sys/ufs/ufs/dinode.h`
//! (inodes) and `sys/ufs/ufs/dir.h` (directory entries), and checked against what FreeBSD's own
//! kernel shows of images made by `newfs` and `makefs`. The same family is FreeBSD's UFS,
//! NetBSD's and OpenBSD's FFSv1/FFSv2 and Solaris UFS.
//!
//! Supported:
//! - UFS2 (magic 0x19540119, and NetBSD's FFSv2ea 0x19012038) and UFS1 (0x011954), found where
//!   FreeBSD looks for them (64 KiB, 8 KiB, 0, 256 KiB), in either byte order: a big-endian
//!   filesystem (SPARC, big-endian NetBSD ports, `makefs -B be`) is read in its own order.
//! - Any block size from 4 KiB to 64 KiB with 1, 2, 4 or 8 fragments per block; cylinder
//!   groups with UFS1's rotating `cgoffset`/`cgmask` placement.
//! - 256-byte UFS2 inodes (64-bit times with nanoseconds, creation time, 64-bit block
//!   pointers) and 128-byte UFS1 inodes (32-bit times and pointers; the 16-bit owner fields of
//!   pre-4.4BSD filesystems). Inodes past a UFS2 cylinder group's `cg_initediblk` were never
//!   initialised and are refused, not read.
//! - File data through the 12 direct and 3 indirect pointers (single, double and triple; the
//!   last block may be a run of fragments); zero pointers are holes and read as zeros.
//! - Symlinks stored in the pointer area (shorter than `fs_maxsymlinklen`, or with no blocks on
//!   filesystems that predate the field) and in data blocks.
//! - Directories in 512-byte chunks, in the 4.4BSD format (`d_type` and an 8-bit name length)
//!   and the older one (a 16-bit name length in the disk's byte order), told apart by the
//!   superblock and by the root directory's `.` entry. A damaged chunk is skipped with a
//!   warning; a walk reads each directory block once.
//! - Solaris UFS (illumos `sys/fs/ufs_fs.h`, `ufs_inode.h`), which shares UFS1's magic and
//!   layout and is told apart by its `fs_state + fs_time == FSOKAY` stamp: owners in the
//!   16-bit fields unless they hold `UID_LONG`, else in the 32-bit ones four bytes later than
//!   BSD's; signed seconds with microseconds; the old directory format.
//! - A filesystem that was not cleanly unmounted (imaged while mounted, or after a crash) is
//!   read as it is on disk, with one warning: the soft-updates journal (SU+J `.sujournal`),
//!   gjournal, NetBSD's WAPBL log and a Solaris UFS log that is not fully rolled are not
//!   replayed.
//!
//! Not supported: snapshots (`.snap` files are listed, but reading one is refused: their block
//! pointers mean "not copied" as often as they name data), extended attributes and ACLs
//! (`di_extb`, Solaris shadow inodes), and checksum verification. Inodes that no directory
//! reaches are not listed.
//!
//! UFS1 times: FreeBSD reads the 32-bit seconds as unsigned (1970 to 2106), and so does this
//! reader; NetBSD and OpenBSD read them as signed (1901 to 2038), so on their UFS1 a time with
//! the top bit set is shown 136 years later than they show it. Solaris's are read as signed.

use std::collections::{HashMap, HashSet};

use crate::{
    be16, be32, be64, le16, le32, le64, shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Tree, Volume,
};

const UFS1_MAGIC: u32 = 0x0001_1954;
const UFS2_MAGIC: u32 = 0x1954_0119;
/// NetBSD's FFSv2 with extended attributes: UFS2's layout.
const UFS2EA_MAGIC: u32 = 0x1901_2038;
const CG_MAGIC: u32 = 0x0009_0255;
/// Where FreeBSD looks for a superblock, in its order.
const SUPERBLOCK_OFFSETS: [u64; 4] = [65536, 8192, 0, 262_144];
/// The bytes of `struct fs` read: everything up to and including `fs_magic`.
const SUPERBLOCK_LEN: usize = 1376;
const MAGIC_AT: usize = 1372;
const ROOT: u64 = 2;
const NDADDR: u64 = 12;
const DIRBLKSIZ: usize = 512;
/// `d_type` of a whiteout entry, which names no file.
const DT_WHT: u8 = 14;

/// `fs_flags` bits.
const FS_UNCLEAN: u32 = 0x1;
const FS_NEEDSFSCK: u32 = 0x4;
const FS_SUJ: u32 = 0x8;
const FS_GJOURNAL: u32 = 0x40;
/// Set in `fs_old_flags` once the flags live in the 32-bit `fs_flags`.
const FS_FLAGS_UPDATED: u8 = 0x80;
/// `fs_clean` of Solaris: clean, stable, and logging (whether the log holds changes is in
/// `fs_rolled`).
const FSCLEAN: u8 = 0x1;
const FSSTABLE: u8 = 0x2;
const FSLOG: u8 = 0xFD;
/// `fs_rolled` of a Solaris logging filesystem whose log holds nothing to apply.
const FS_ALL_ROLLED: u32 = 1;
/// `fs_state + fs_time` on a Solaris filesystem.
const FSOKAY: u32 = 0x7c26_9d38;
/// `ic_suid` when the owner is in the 32-bit field.
const UID_LONG: u16 = 0xFFFF;
/// `di_flags`: the file is a snapshot.
const SF_SNAPSHOT: u32 = 0x0020_0000;

/// The byte order of one filesystem.
#[derive(Clone, Copy)]
struct Order {
    big: bool,
}

impl Order {
    fn u16(self, b: &[u8], at: usize) -> u16 {
        if self.big {
            be16(b, at)
        } else {
            le16(b, at)
        }
    }

    fn u32(self, b: &[u8], at: usize) -> u32 {
        if self.big {
            be32(b, at)
        } else {
            le32(b, at)
        }
    }

    fn u64(self, b: &[u8], at: usize) -> u64 {
        if self.big {
            be64(b, at)
        } else {
            le64(b, at)
        }
    }

    fn i32(self, b: &[u8], at: usize) -> i32 {
        self.u32(b, at) as i32
    }
}

/// What the superblock says about the layout.
struct Geometry {
    order: Order,
    ufs2: bool,
    bsize: u64,
    fsize: u64,
    /// Fragments per block.
    frag: u64,
    ncg: u64,
    ipg: u64,
    fpg: u64,
    /// Fragment offsets in a cylinder group of its header and of its inode blocks.
    cblkno: u64,
    iblkno: u64,
    /// UFS1: cylinder groups start `cgoffset * (c & !cgmask)` fragments after `fpg * c`.
    cgoffset: i64,
    cgmask: u32,
    /// Fragments in the filesystem.
    frags: u64,
    inode_size: u64,
    maxsymlinklen: i32,
    old_dirs: bool,
    old_ids: bool,
    /// Written by Solaris: other owner fields and microsecond times.
    solaris: bool,
    /// Why the filesystem may not be what a mount would show, when it was in use.
    note: Option<String>,
}

fn parse_superblock(sb: &[u8], at: u64) -> Result<Geometry> {
    let magics = [UFS1_MAGIC, UFS2_MAGIC, UFS2EA_MAGIC];
    let (order, magic) = if magics.contains(&le32(sb, MAGIC_AT)) {
        (Order { big: false }, le32(sb, MAGIC_AT))
    } else if magics.contains(&be32(sb, MAGIC_AT)) {
        (Order { big: true }, be32(sb, MAGIC_AT))
    } else {
        return Err(Error::corrupt("no UFS superblock magic"));
    };
    let o = order;
    let ufs2 = magic != UFS1_MAGIC;
    // A UFS2 superblock records where it is; one found elsewhere is a backup or a stray copy.
    if ufs2 && o.u64(sb, 1000) != at {
        return Err(Error::corrupt(format!("UFS2 superblock at {at} says it is at {}", o.u64(sb, 1000))));
    }
    let (bsize, fsize, frag) = (o.i32(sb, 48), o.i32(sb, 52), o.i32(sb, 56));
    let valid = |v: i32, lo: i32, hi: i32| (lo..=hi).contains(&v) && (v as u32).is_power_of_two();
    if !valid(bsize, 4096, 65536) || !valid(fsize, 512, bsize) || bsize / fsize != frag || frag > 8 {
        return Err(Error::corrupt(format!("block size {bsize}, fragment size {fsize}, {frag} fragments per block")));
    }
    let (bsize, fsize, frag) = (bsize as u64, fsize as u64, frag as u64);
    let inode_size = if ufs2 { 256 } else { 128 };
    if u64::from(o.u32(sb, 120)) != bsize / inode_size {
        return Err(Error::corrupt(format!("{} inodes per block", o.u32(sb, 120))));
    }
    let (ncg, ipg, fpg) = (u64::from(o.u32(sb, 44)), u64::from(o.u32(sb, 184)), o.i32(sb, 188));
    let (cblkno, iblkno) = (o.i32(sb, 12), o.i32(sb, 16));
    // A UFS1 superblock that was updated in place (`FS_FLAGS_UPDATED`) keeps its size in the
    // 64-bit field as well, and only there once the filesystem was grown (`resize_ffs`).
    let updated = sb.get(211).is_some_and(|flags| flags & FS_FLAGS_UPDATED != 0);
    let frags = match (ufs2, o.u64(sb, 1080)) {
        (true, size) => size,
        (false, size) if updated && size != 0 => size,
        (false, _) => u64::from(o.u32(sb, 36)),
    };
    if ncg == 0 || ipg == 0 || fpg <= 0 || cblkno < 0 || iblkno < 0 || frags == 0 {
        return Err(Error::corrupt("cylinder group geometry"));
    }
    let fpg = fpg as u64;
    // The inode blocks fit in a cylinder group, inode numbers fit in 32 bits, and the groups
    // cover the filesystem's size (so a forged count cannot outgrow it).
    let inode_frags = (ipg * inode_size).div_ceil(fsize);
    if iblkno as u64 + inode_frags > fpg || ncg * ipg > 1 << 32 || ncg > frags.div_ceil(fpg) {
        return Err(Error::corrupt(format!("{ncg} cylinder groups of {ipg} inodes and {fpg} fragments")));
    }
    let maxsymlinklen = o.i32(sb, 1320);
    let old_flags = sb.get(211).copied().unwrap_or(0);
    let flags = if old_flags & FS_FLAGS_UPDATED != 0 { o.u32(sb, 1312) } else { u32::from(old_flags) };
    let clean = sb.get(209).copied().unwrap_or(0);
    // Solaris keeps `fs_state` where its platform's `fs_npsect` is not.
    let state_at = if order.big { 1336 } else { 132 };
    let solaris = !ufs2 && o.u32(sb, state_at).wrapping_add(o.u32(sb, 32)) == FSOKAY;
    let note = match solaris {
        true => solaris_note(clean, o.u32(sb, 4)),
        false => unclean_note(clean, flags),
    };
    Ok(Geometry {
        order,
        ufs2,
        bsize,
        fsize,
        frag,
        ncg,
        ipg,
        fpg,
        cblkno: cblkno as u64,
        iblkno: iblkno as u64,
        cgoffset: i64::from(o.i32(sb, 24)),
        cgmask: o.u32(sb, 28),
        frags,
        inode_size,
        maxsymlinklen,
        old_dirs: maxsymlinklen <= 0,
        // 4.2BSD-format inodes keep 16-bit owners where 4.4BSD has the free-list link (Solaris
        // has its log's address in that superblock field).
        old_ids: !ufs2 && !solaris && o.i32(sb, 1324) < 2,
        solaris,
        note,
    })
}

const UNCLEAN: &str =
    "the filesystem was in use when it was imaged (not cleanly unmounted) and is read as it is on disk";
const STALE: &str = "the files written last may be missing, out of date or unreadable";

/// The warning for a BSD filesystem that was in use when imaged, from `fs_clean` and `fs_flags`.
fn unclean_note(clean: u8, flags: u32) -> Option<String> {
    // FreeBSD writes 1 when clean and 0 while mounted; NetBSD keeps "is clean" as bit 0.
    if clean & 1 != 0 && flags & (FS_UNCLEAN | FS_NEEDSFSCK) == 0 {
        return None;
    }
    let journal = if flags & FS_SUJ != 0 {
        "; its soft-updates journal (.sujournal) is not replayed"
    } else if flags & FS_GJOURNAL != 0 {
        "; its gjournal is not replayed"
    } else {
        ""
    };
    Some(format!("{UNCLEAN}{journal}: {STALE}"))
}

/// The warning for a Solaris filesystem: clean or stable, or logging with nothing left to roll.
fn solaris_note(clean: u8, rolled: u32) -> Option<String> {
    match clean {
        FSCLEAN | FSSTABLE => None,
        FSLOG if rolled == FS_ALL_ROLLED => None,
        FSLOG => Some(format!("{UNCLEAN}; its UFS log is not rolled into it: {STALE}")),
        _ => Some(format!("{UNCLEAN}: {STALE}")),
    }
}

/// Finds the superblock: its geometry and byte offset.
fn find_superblock(image: &dyn ReadAt) -> Result<Geometry> {
    let mut first_error = None;
    let mut sb = [0u8; SUPERBLOCK_LEN];
    for at in SUPERBLOCK_OFFSETS {
        if image.read_at(at, &mut sb).is_err() {
            continue;
        }
        match parse_superblock(&sb, at) {
            Ok(g) => return Ok(g),
            // A magic number with damage around it says more than "no magic" elsewhere.
            Err(e) if first_error.is_none() && matches!(&e, Error::Corrupt(m) if m != "no UFS superblock magic") => {
                first_error = Some(e);
            }
            Err(_) => {}
        }
    }
    Err(first_error.unwrap_or_else(|| Error::corrupt("no UFS superblock")))
}

/// Recognizes a UFS1 or UFS2 superblock where FreeBSD looks for one.
pub fn probe(image: &dyn ReadAt) -> bool {
    find_superblock(image).is_ok()
}

/// The parts of an inode this reader uses.
#[derive(Clone, Copy)]
struct Inode {
    mode: u16,
    links: u16,
    uid: u32,
    gid: u32,
    size: u64,
    /// 512-byte sectors held: data, indirect and extended-attribute blocks.
    blocks: u64,
    flags: u32,
    /// The 12 direct and 3 indirect pointers, as fragment numbers.
    ptrs: [u64; 15],
    /// The raw pointer area, which holds a short symlink's target.
    area: [u8; 120],
    area_len: usize,
    atime: Option<i64>,
    mtime: Option<i64>,
    ctime: Option<i64>,
    btime: Option<i64>,
}

/// Seconds and nanoseconds to nanoseconds; `None` for zero. Nanoseconds out of range are dropped.
fn time(secs: i64, nsec: i32) -> Option<i64> {
    let nsec = if (0..1_000_000_000).contains(&nsec) { i64::from(nsec) } else { 0 };
    if secs == 0 && nsec == 0 {
        return None;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(nsec)
}

impl Inode {
    fn parse(g: &Geometry, raw: &[u8]) -> Inode {
        let o = g.order;
        let mut ptrs = [0u64; 15];
        let mut area = [0u8; 120];
        if g.ufs2 {
            for (i, p) in ptrs.iter_mut().enumerate() {
                *p = o.u64(raw, 112 + 8 * i);
            }
            area.copy_from_slice(raw.get(112..232).unwrap_or(&[0; 120]));
            Inode {
                mode: o.u16(raw, 0),
                links: o.u16(raw, 2),
                uid: o.u32(raw, 4),
                gid: o.u32(raw, 8),
                size: o.u64(raw, 16),
                blocks: o.u64(raw, 24),
                flags: o.u32(raw, 88),
                ptrs,
                area,
                area_len: 120,
                atime: time(o.u64(raw, 32) as i64, o.i32(raw, 68)),
                mtime: time(o.u64(raw, 40) as i64, o.i32(raw, 64)),
                ctime: time(o.u64(raw, 48) as i64, o.i32(raw, 72)),
                btime: time(o.u64(raw, 56) as i64, o.i32(raw, 76)),
            }
        } else {
            for (i, p) in ptrs.iter_mut().enumerate() {
                *p = u64::from(o.u32(raw, 40 + 4 * i));
            }
            area[..60].copy_from_slice(raw.get(40..100).unwrap_or(&[0; 60]));
            let short = |at: usize, long: usize| match o.u16(raw, at) {
                UID_LONG => o.u32(raw, long),
                id => u32::from(id),
            };
            let (uid, gid) = if g.solaris {
                (short(4, 116), short(6, 120))
            } else if g.old_ids {
                (u32::from(o.u16(raw, 4)), u32::from(o.u16(raw, 6)))
            } else {
                (o.u32(raw, 112), o.u32(raw, 116))
            };
            // FreeBSD's unsigned seconds and nanoseconds; Solaris's signed seconds and microseconds.
            let stamp = |at: usize| match g.solaris {
                true => time(i64::from(o.i32(raw, at)), o.i32(raw, at + 4).saturating_mul(1000)),
                false => time(i64::from(o.u32(raw, at)), o.i32(raw, at + 4)),
            };
            Inode {
                mode: o.u16(raw, 0),
                links: o.u16(raw, 2),
                uid,
                gid,
                size: o.u64(raw, 8),
                blocks: u64::from(o.u32(raw, 104)),
                flags: o.u32(raw, 100),
                ptrs,
                area,
                area_len: 60,
                atime: stamp(16),
                mtime: stamp(24),
                ctime: stamp(32),
                btime: None,
            }
        }
    }

    fn kind(&self) -> Kind {
        match self.mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Directory,
            0o120000 => Kind::Symlink,
            _ => Kind::Other,
        }
    }
}

/// A run of logical blocks that maps to consecutive fragments (`phys`, a block apart), or a hole.
struct Run {
    phys: Option<u64>,
    len: u64,
}

/// Recently read indirect blocks, for one read or walk.
struct Blocks {
    entries: Vec<(u64, Vec<u8>)>,
    next: usize,
}

impl Blocks {
    fn new() -> Self {
        Blocks { entries: Vec::new(), next: 0 }
    }

    fn get<R: ReadAt>(&mut self, fs: &Ufs<R>, frag: u64) -> Result<&[u8]> {
        if let Some(i) = self.entries.iter().position(|(b, _)| *b == frag) {
            return Ok(&self.entries[i].1);
        }
        let mut data = vec![0u8; fs.g.bsize as usize];
        fs.read_frags(frag, 0, &mut data)?;
        let i = if self.entries.len() < 8 {
            self.entries.push((frag, data));
            self.entries.len() - 1
        } else {
            let i = self.next;
            self.entries[i] = (frag, data);
            self.next = (i + 1) % 8;
            i
        };
        Ok(&self.entries[i].1)
    }
}

/// An opened UFS1 or UFS2 filesystem.
pub struct Ufs<R> {
    image: R,
    g: Geometry,
}

impl<R: ReadAt> Ufs<R> {
    pub fn open(image: R) -> Result<Ufs<R>> {
        let g = find_superblock(&image)?;
        let mut fs = Ufs { image, g };
        let root = fs.inode(ROOT, &mut HashMap::new())?;
        if root.kind() != Kind::Directory {
            return Err(Error::corrupt("root inode is not a directory"));
        }
        fs.g.old_dirs = fs.root_dir_format(&root).unwrap_or(fs.g.old_dirs);
        Ok(fs)
    }

    /// Whether the root's `.` entry is in the old directory format; `None` when it does not
    /// say. A `fs_maxsymlinklen` of 0 usually marks the old format, but Solaris, which keeps
    /// it, uses that field for something else.
    fn root_dir_format(&self, root: &Inode) -> Option<bool> {
        let mut head = [0u8; 12];
        let Run { phys: Some(frag), .. } = self.map(root, 0, &mut Blocks::new()).ok()? else { return None };
        self.read_frags(frag, 0, &mut head).ok()?;
        if head[8..10] != *b".\0" {
            return None;
        }
        match (head[7], self.g.order.u16(&head, 6)) {
            (1, _) => Some(false),
            (_, 1) => Some(true),
            _ => None,
        }
    }

    /// First fragment of cylinder group `c`.
    fn cg_start(&self, c: u64) -> Option<u64> {
        let base = self.g.fpg.checked_mul(c)?;
        if self.g.ufs2 {
            return Some(base);
        }
        let rotation = self.g.cgoffset.checked_mul(i64::from(c as u32 & !self.g.cgmask))?;
        u64::try_from(i64::try_from(base).ok()?.checked_add(rotation)?).ok()
    }

    /// Reads `buf.len()` bytes `within` bytes past fragment `frag`, refusing reads past the
    /// filesystem's end.
    fn read_frags(&self, frag: u64, within: u64, buf: &mut [u8]) -> Result<()> {
        let end = self.g.frags.saturating_mul(self.g.fsize);
        let at = frag.checked_mul(self.g.fsize).and_then(|a| a.checked_add(within));
        match at {
            Some(at) if at.checked_add(buf.len() as u64).is_some_and(|e| e <= end) => {
                Ok(self.image.read_at(at, buf)?)
            }
            _ => Err(Error::corrupt(format!("fragment {frag} is past the end of the filesystem"))),
        }
    }

    /// `cg_initediblk` of UFS2 cylinder group `c`: inodes from there on were never written.
    /// `None` when the group's header is damaged.
    fn initialised(&self, c: u64) -> Option<u64> {
        let mut cg = [0u8; 124];
        self.read_frags(self.cg_start(c)?.checked_add(self.g.cblkno)?, 0, &mut cg).ok()?;
        let o = self.g.order;
        (o.u32(&cg, 4) == CG_MAGIC && u64::from(o.u32(&cg, 12)) == c).then(|| u64::from(o.u32(&cg, 120)))
    }

    /// The byte offset of inode `ino`, after checking it was initialised (`cgs` caches the
    /// cylinder groups' `cg_initediblk`).
    fn inode_pos(&self, ino: u64, cgs: &mut HashMap<u64, Option<u64>>) -> Result<u64> {
        let g = &self.g;
        if ino >= g.ncg * g.ipg {
            return Err(Error::corrupt(format!("inode {ino} out of range")));
        }
        let (c, index) = (ino / g.ipg, ino % g.ipg);
        if g.ufs2 {
            match *cgs.entry(c).or_insert_with(|| self.initialised(c)) {
                None => return Err(Error::corrupt(format!("inode {ino}: cylinder group {c} header is damaged"))),
                Some(n) if index >= n => return Err(Error::corrupt(format!("inode {ino} was never initialised"))),
                Some(_) => {}
            }
        }
        let frag = self.cg_start(c).and_then(|s| s.checked_add(g.iblkno));
        frag.and_then(|f| f.checked_mul(g.fsize))
            .and_then(|b| b.checked_add(index * g.inode_size))
            .ok_or_else(|| Error::corrupt(format!("inode {ino} out of range")))
    }

    fn inode(&self, ino: u64, cgs: &mut HashMap<u64, Option<u64>>) -> Result<Inode> {
        let pos = self.inode_pos(ino, cgs)?;
        let mut raw = [0u8; 256];
        let raw = &mut raw[..self.g.inode_size as usize];
        self.image.read_at(pos, raw)?;
        Ok(Inode::parse(&self.g, raw))
    }

    /// Maps logical block `lbn` of `inode` through its direct and indirect pointers.
    fn map(&self, inode: &Inode, lbn: u64, cache: &mut Blocks) -> Result<Run> {
        let g = &self.g;
        let per = if g.ufs2 { g.bsize / 8 } else { g.bsize / 4 };
        let pointer = |data: &[u8], i: u64| match g.ufs2 {
            true => g.order.u64(data, (i * 8) as usize),
            false => u64::from(g.order.u32(data, (i * 4) as usize)),
        };
        // The run of pointers from `i` on (of `count`) that are all zero or a block apart.
        let run = |get: &dyn Fn(u64) -> u64, i: u64, count: u64| {
            let phys = get(i);
            let mut len = 1;
            while i + len < count {
                let next = get(i + len);
                if (phys == 0 && next != 0) || (phys != 0 && Some(next) != phys.checked_add(len * g.frag)) {
                    break;
                }
                len += 1;
            }
            Run { phys: (phys != 0).then_some(phys), len }
        };
        if lbn < NDADDR {
            return Ok(run(&|i| inode.ptrs[i as usize], lbn, NDADDR));
        }
        let mut rel = lbn - NDADDR;
        let mut span = per;
        let mut slot = NDADDR as usize;
        while rel >= span {
            rel -= span;
            span = span.saturating_mul(per);
            slot += 1;
            if slot > 14 {
                return Ok(Run { phys: None, len: u64::MAX / 2 });
            }
        }
        let mut block = inode.ptrs[slot];
        loop {
            if block == 0 {
                return Ok(Run { phys: None, len: span - rel });
            }
            span /= per;
            let index = rel / span;
            rel %= span;
            let data = cache.get(self, block)?;
            if span == 1 {
                return Ok(run(&|i| pointer(data, i), index, per));
            }
            block = pointer(data, index);
        }
    }

    /// Reads file content of an already-parsed inode.
    fn read_inode(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        let n = (inode.size - offset).min(buf.len() as u64) as usize;
        let buf = &mut buf[..n];
        let bs = self.g.bsize;
        let mut cache = Blocks::new();
        let mut done = 0;
        while done < n {
            let pos = offset + done as u64;
            let (lbn, within) = (pos / bs, pos % bs);
            let run = self.map(inode, lbn, &mut cache)?;
            let take = run.len.saturating_mul(bs).saturating_sub(within).min((n - done) as u64) as usize;
            let out = &mut buf[done..done + take];
            match run.phys {
                None => out.fill(0),
                Some(frag) => self.read_frags(frag, within, out)?,
            }
            done += take;
        }
        Ok(n)
    }

    /// Whether a symlink's target is in the pointer area: shorter than `fs_maxsymlinklen`, or
    /// with no blocks at all (filesystems older than the field), as FreeBSD's `ufs_readlink`.
    fn inline_symlink(&self, inode: &Inode) -> bool {
        inode.size < self.g.maxsymlinklen.max(0) as u64 || inode.blocks == 0
    }

    fn symlink_target(&self, inode: &Inode) -> Result<String> {
        if inode.size > crate::MAX_PATH as u64 {
            return Err(Error::corrupt(format!("symlink of {} bytes", inode.size)));
        }
        let target = if self.inline_symlink(inode) {
            let area = &inode.area[..inode.area_len];
            area.get(..inode.size as usize)
                .ok_or_else(|| Error::corrupt("inline symlink longer than the inode"))?
                .to_vec()
        } else {
            let mut buf = vec![0u8; inode.size as usize];
            let n = self.read_inode(inode, 0, &mut buf)?;
            buf.truncate(n);
            buf
        };
        Ok(String::from_utf8_lossy(&target).into_owned())
    }

    /// Lists the entries of one directory block into `out`, a 512-byte chunk at a time.
    /// Returns the number of damaged chunks (the rest of each is skipped).
    fn scan_block(&self, block: &[u8], out: &mut Entries) -> usize {
        let o = self.g.order;
        let mut damaged = 0;
        for chunk in block.chunks(DIRBLKSIZ) {
            let mut off = 0;
            while off + 8 <= chunk.len() {
                let ino = o.u32(chunk, off);
                let reclen = usize::from(o.u16(chunk, off + 4));
                let (dtype, namlen) = match self.g.old_dirs {
                    true => (0, usize::from(o.u16(chunk, off + 6))),
                    false => (chunk[off + 6], usize::from(chunk[off + 7])),
                };
                if reclen < 8 || reclen % 4 != 0 || off + reclen > chunk.len() || namlen > 255 || 8 + namlen > reclen {
                    damaged += 1;
                    break;
                }
                let name = &chunk[off + 8..off + 8 + namlen];
                if ino != 0 && dtype != DT_WHT && name != b"." && name != b".." && !out.push(u64::from(ino), name) {
                    return damaged;
                }
                off += reclen;
            }
        }
        damaged
    }
}

/// The state of one walk: the directory blocks already read, cached cylinder groups and
/// indirect blocks, and a reusable buffer.
struct Walk<'w, R> {
    fs: &'w Ufs<R>,
    seen: HashSet<u64>,
    cgs: HashMap<u64, Option<u64>>,
    block: Vec<u8>,
    cache: Blocks,
}

impl<R: ReadAt> Tree for Walk<'_, R> {
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let fs = self.fs;
        let inode = fs.inode(dir, &mut self.cgs)?;
        if inode.kind() != Kind::Directory {
            return Err(Error::corrupt("not a directory"));
        }
        let bs = fs.g.bsize;
        let blocks = inode.size.div_ceil(bs);
        let mut lbn = 0;
        while lbn < blocks && !out.full() {
            let run = fs.map(&inode, lbn, &mut self.cache)?;
            let len = run.len.min(blocks - lbn);
            // UFS never leaves a hole in a directory (fsck reports one), so a hole is damage, and
            // stopping there keeps a forged size from walking an empty block map for long.
            let Some(first) = run.phys else {
                warn(format!("{}: hole at directory block {lbn}; rest skipped", shown(path)));
                return Ok(());
            };
            for i in 0..len {
                let frag = first + i * fs.g.frag;
                if !self.seen.insert(frag) {
                    warn(format!(
                        "{}: directory block {} was already read for another directory; rest skipped",
                        shown(path),
                        lbn + i
                    ));
                    return Ok(());
                }
                let n = bs.min(inode.size - (lbn + i) * bs) as usize;
                self.block.resize(n, 0);
                fs.read_frags(frag, 0, &mut self.block)?;
                let damaged = fs.scan_block(&self.block, out);
                if damaged > 0 {
                    warn(format!(
                        "{}: directory block {}: {damaged} damaged 512-byte chunks, rest of each skipped",
                        shown(path),
                        lbn + i
                    ));
                }
                if out.full() {
                    return Ok(());
                }
            }
            lbn += len;
        }
        Ok(())
    }

    fn node(&mut self, ino: u64, path: &str, warn: &mut dyn FnMut(String)) -> Result<Node> {
        let fs = self.fs;
        let inode = fs.inode(ino, &mut self.cgs)?;
        if inode.mode == 0 {
            return Err(Error::corrupt(format!("entry points to unused inode {ino}")));
        }
        let kind = inode.kind();
        let mut link_target = None;
        if kind == Kind::Symlink {
            match fs.symlink_target(&inode) {
                Ok(target) => link_target = Some(target),
                Err(e) => warn(format!("{}: symlink target: {e}", shown(path))),
            }
        }
        Ok(Node {
            path: String::new(),
            inode: ino,
            kind,
            mode: u32::from(inode.mode),
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            allocated: inode.blocks.saturating_mul(512),
            links: u32::from(inode.links),
            accessed: inode.atime,
            modified: inode.mtime,
            changed: inode.ctime,
            created: inode.btime,
            link_target,
        })
    }
}

impl<R: ReadAt> Volume for Ufs<R> {
    fn kind(&self) -> &'static str {
        "ufs"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        if let Some(note) = &self.g.note {
            warn(format!("ufs: {note}"));
        }
        let mut walk =
            Walk { fs: self, seen: HashSet::new(), cgs: HashMap::new(), block: Vec::new(), cache: Blocks::new() };
        walk_tree("ufs", &mut walk, ROOT, visit, warn)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let parsed = self.inode(inode, &mut HashMap::new())?;
        match parsed.kind() {
            _ if parsed.mode == 0 => return Err(Error::corrupt(format!("inode {inode} is not in use"))),
            Kind::Other => {
                return Err(Error::unsupported(format!("inode {inode} is not a file, directory or symlink")))
            }
            Kind::Symlink if self.inline_symlink(&parsed) => {
                let target = self.symlink_target(&parsed)?.into_bytes();
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(target.len());
                let n = buf.len().min(target.len() - start);
                buf[..n].copy_from_slice(&target[start..start + n]);
                return Ok(n);
            }
            _ if parsed.flags & SF_SNAPSHOT != 0 && !self.g.solaris => {
                return Err(Error::unsupported(format!("inode {inode} is a UFS snapshot, which is not read")));
            }
            _ => {}
        }
        self.read_inode(&parsed, offset, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unclean_notes() {
        assert_eq!(unclean_note(1, 0), None);
        assert_eq!(unclean_note(3, 0), None);
        assert!(unclean_note(0, 0).is_some_and(|n| !n.contains("journal")));
        assert!(unclean_note(2, 0).is_some());
        assert!(unclean_note(0, FS_SUJ).is_some_and(|n| n.contains("soft-updates journal")));
        assert!(unclean_note(1, FS_NEEDSFSCK).is_some());
        assert_eq!(solaris_note(FSCLEAN, 0), None);
        assert_eq!(solaris_note(FSLOG, FS_ALL_ROLLED), None);
        assert!(solaris_note(FSLOG, 2).is_some_and(|n| n.contains("UFS log")));
        assert!(solaris_note(0, 0).is_some());
    }

    /// A UFS1 filesystem grown by NetBSD's `resize_ffs` keeps its new size in the 64-bit
    /// field only; the old 32-bit one still holds the size it was made with.
    #[test]
    fn a_grown_ufs1_takes_its_size_from_the_64_bit_field() {
        let mut sb = vec![0u8; SUPERBLOCK_LEN];
        let mut put = |at: usize, v: u32| sb[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(MAGIC_AT, UFS1_MAGIC);
        for (at, value) in [(48, 16384), (52, 2048), (56, 8), (120, 128), (44, 23), (184, 23552), (188, 94136)] {
            put(at, value);
        }
        put(12, 16);
        put(16, 24);
        put(36, 975_872); // the size before it was grown: 11 groups
        put(1080, 2_096_640);
        put(1320, 60);
        put(1324, 2);
        sb[209] = 1;
        assert!(parse_superblock(&sb, 8192).is_err(), "without the updated flag the old size stands");
        sb[211] = FS_FLAGS_UPDATED;
        let g = parse_superblock(&sb, 8192).unwrap();
        assert_eq!((g.ncg, g.frags, g.ufs2), (23, 2_096_640, false));
    }

    #[test]
    fn times() {
        assert_eq!(time(0, 0), None);
        assert_eq!(time(-1, 0), Some(-1_000_000_000));
        assert_eq!(time(1, 5), Some(1_000_000_005));
        assert_eq!(time(1, 1_000_000_000), Some(1_000_000_000));
        assert_eq!(time(i64::MAX, 0), None);
    }
}

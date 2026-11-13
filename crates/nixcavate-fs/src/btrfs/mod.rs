//! Btrfs, read-only.
//!
//! Written from the Btrfs documentation's "On-disk Format" and the kernel's
//! `include/uapi/linux/btrfs_tree.h`, `fs/btrfs/volumes.c` (chunk mapping), `fs/btrfs/lzo.c`
//! and `fs/btrfs/inode.c`. Every on-disk integer is little-endian.
//!
//! Supported:
//! - the primary superblock (the copies at 64 MiB and 256 GiB when it is unreadable), the
//!   bootstrap chunk array and the chunk tree. Block groups with the single, DUP, RAID1, RAID1C3
//!   and RAID1C4 profiles are read from the copy on this device; mixed block groups too;
//! - the root tree and every file tree (subvolume): B-tree nodes of any node size up to
//!   64 KiB. Checksums are NOT verified; every block's recorded address, filesystem id and
//!   level are, and its owner for the root and chunk trees. A block reached twice in one scan
//!   is damage, and one walk or read makes a bounded number of block fetches;
//! - inodes (size, mode, uid, gid, link count, access, change, modification and creation
//!   times with nanoseconds), directory index entries, symlinks (an inline extent), and file
//!   extents: inline, regular, preallocated (zeros), holes with or without the `no-holes`
//!   feature, extents shared after a reflink or a snapshot, and zlib, LZO and zstd compression.
//!   LZO is decoded here; zlib and zstd go through the [`Decompress`] the volume is given, and
//!   without one such a file is an `Unsupported` read error.
//!
//! What a walk shows is the tree the installed system mounts:
//! - `/` is the default subvolume (the root tree's `default` entry). When that is the top
//!   level (5) and the top level has no `etc`, but a writable subvolume directly inside it
//!   does, that subvolume is `/` instead (`@` first, then `root`, then the lowest id): the
//!   Fedora, Ubuntu and Arch layouts.
//! - `/etc/fstab` of that root is read: each `btrfs` line with `subvol=` or `subvolid=` (or
//!   neither: the default subvolume) whose device is not another filesystem's `UUID=` or
//!   `LABEL=` puts that subvolume at its mount point, replacing what the root has there.
//! - A writable subvolume inside a walked one is walked in place, where the system shows it.
//! - Read-only subvolumes (snapshots, such as snapper's under `.snapshots`) are listed as
//!   empty directories and named in one warning; their files would repeat the live ones.
//!   A subvolume already shown elsewhere (the root, a mount) is also an empty directory where
//!   it is linked a second time. Subvolumes reached neither way are named in one warning.
//!
//! Node inode numbers: the low 48 bits are the inode number in its subvolume and bits 48 to
//! 62 the subvolume's slot (0 for the subvolume read as `/`, so its files carry their own
//! inode numbers); bit 63 marks a subvolume shown as an empty directory.
//!
//! Not supported: multi-device filesystems beyond the copy on this device (a block group with
//! no stripe here is named in a warning and its files are not read), the RAID0, RAID10, RAID5
//! and RAID6 profiles (same), checksum verification, the log tree (fsyncs since the last
//! commit are not replayed), walking snapshots, zoned devices, the extent tree v2 and RAID
//! stripe tree formats (the volume is not opened), encrypted extents, extended attributes,
//! send streams, quotas.

mod items;
mod lzo;
mod tree;

use std::collections::{HashMap, HashSet};

use items::{Inode, DIR_INDEX, DIR_ITEM, EXTENT_DATA, INODE_ITEM, ROOT_BACKREF, ROOT_ITEM};
use tree::{Cache, Chunks, Disk, Key, Root, MAX_LEVEL};

use crate::{le32, le64, shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Volume};

/// The compression of a file extent that a [`Decompress`] handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    Zlib,
    Zstd,
}

/// Decompresses file extents for the reader, which has no dependencies of its own.
pub trait Decompress: Sync {
    /// Appends the decompressed form of `input` (one zlib stream or one zstd frame) to
    /// `out`, at most `limit` bytes: output past the limit is dropped, not an error.
    fn decompress(&self, kind: Compression, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()>;
}

const MAGIC: &[u8; 8] = b"_BHRfS_M";
/// The superblock and its copies.
const SUPERS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
const SUPER_SIZE: usize = 4096;
/// `sys_chunk_array` holds at most this many bytes.
const SYS_CHUNK_ARRAY: usize = 2048;

const ROOT_TREE: u64 = 1;
const CHUNK_TREE: u64 = 3;
const FS_TREE: u64 = 5;
const FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
const FIRST_FREE: u64 = 256;
const LAST_FREE: u64 = -256i64 as u64;

const INCOMPAT_METADATA_UUID: u64 = 1 << 10;
const INCOMPAT_ZONED: u64 = 1 << 12;
const INCOMPAT_EXTENT_TREE_V2: u64 = 1 << 13;
const INCOMPAT_RAID_STRIPE_TREE: u64 = 1 << 14;
/// Mixed backrefs, default subvolume, mixed groups, LZO, zstd, big metadata, extended inode
/// refs, RAID5/6, skinny metadata, no holes, metadata uuid, RAID1C3/4, simple quotas: none of
/// them changes how the structures read here are laid out beyond what is handled.
const KNOWN_INCOMPAT: u64 = 0xfff | 1 << 16;

/// Subvolumes accepted: the slot must fit 15 bits of a node's inode number.
const MAX_SUBVOLUMES: usize = 1 << 15;
const INO_BITS: u32 = 48;
const STUB: u64 = 1 << 63;
/// A compressed extent holds at most 128 KiB, before and after compression.
const MAX_EXTENT: u64 = 128 << 10;
/// Longest symlink target read (`PATH_MAX` less its NUL).
const MAX_SYMLINK: u64 = 4095;
const MAX_FSTAB: u64 = 1 << 20;
const MAX_MOUNTS: usize = 256;
/// Paths and names a warning lists before it only counts.
const NAMES_SHOWN: usize = 10;

const S_IFMT: u32 = 0o170000;

fn kind(mode: u32) -> Kind {
    match mode & S_IFMT {
        0o100000 => Kind::File,
        0o040000 => Kind::Directory,
        0o120000 => Kind::Symlink,
        _ => Kind::Other,
    }
}

/// The superblock fields the reader uses.
struct Super {
    /// The filesystem uuid users see, and the id tree blocks carry.
    uuid: [u8; 16],
    block_id: [u8; 16],
    label: String,
    root: u64,
    root_level: u8,
    chunk_root: u64,
    chunk_level: u8,
    log_root: u64,
    num_devices: u64,
    devid: u64,
    sectorsize: usize,
    nodesize: usize,
    array: Vec<u8>,
}

fn parse_superblock(sb: &[u8], at: u64) -> Result<Super> {
    if sb.get(0x40..0x48) != Some(MAGIC.as_slice()) {
        return Err(Error::corrupt("no Btrfs superblock magic"));
    }
    if le64(sb, 0x30) != at {
        return Err(Error::corrupt("superblock records another address"));
    }
    let sectorsize = le32(sb, 0x90);
    let nodesize = le32(sb, 0x94);
    if !sectorsize.is_power_of_two() || !(4096..=65536).contains(&sectorsize) {
        return Err(Error::corrupt(format!("sector size {sectorsize}")));
    }
    if !nodesize.is_power_of_two() || nodesize < sectorsize || nodesize > 65536 {
        return Err(Error::corrupt(format!("node size {nodesize}")));
    }
    let incompat = le64(sb, 0xbc);
    for (bit, what) in [
        (INCOMPAT_ZONED, "zoned device"),
        (INCOMPAT_EXTENT_TREE_V2, "extent tree v2"),
        (INCOMPAT_RAID_STRIPE_TREE, "RAID stripe tree"),
    ] {
        if incompat & bit != 0 {
            return Err(Error::unsupported(format!("Btrfs {what}")));
        }
    }
    if incompat & !KNOWN_INCOMPAT != 0 {
        return Err(Error::unsupported(format!("Btrfs incompatible features {incompat:#x}")));
    }
    let array_len = le32(sb, 0xa0) as usize;
    let (root_level, chunk_level) = (sb[0xc6], sb[0xc7]);
    if array_len > SYS_CHUNK_ARRAY || root_level > MAX_LEVEL || chunk_level > MAX_LEVEL {
        return Err(Error::corrupt("superblock fields out of range"));
    }
    let id = |at: usize| -> [u8; 16] { crate::array(sb, at) };
    let uuid = id(0x20);
    let label = &sb[0x12b..0x22b];
    let label = &label[..label.iter().position(|&c| c == 0).unwrap_or(label.len())];
    Ok(Super {
        uuid,
        block_id: if incompat & INCOMPAT_METADATA_UUID != 0 { id(0x23b) } else { uuid },
        label: String::from_utf8_lossy(label).into_owned(),
        root: le64(sb, 0x50),
        root_level,
        chunk_root: le64(sb, 0x58),
        chunk_level,
        log_root: le64(sb, 0x60),
        num_devices: le64(sb, 0x88),
        devid: le64(sb, 0xc9),
        sectorsize: sectorsize as usize,
        nodesize: nodesize as usize,
        array: sb[0x32b..0x32b + array_len].to_vec(),
    })
}

/// Recognizes a Btrfs superblock at 64 KiB into `image`.
pub fn probe(image: &dyn ReadAt) -> bool {
    let mut magic = [0u8; 8];
    image.read_at(SUPERS[0] + 0x40, &mut magic).is_ok() && &magic == MAGIC
}

fn uuid_string(u: &[u8; 16]) -> String {
    let hex: String = u.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// One subvolume (file tree).
struct Subvol {
    id: u64,
    root: Root,
    /// Inode number of its top directory (256).
    dirid: u64,
    readonly: bool,
    /// Its name in the directory that links it, from the root back reference.
    name: String,
    parent: u64,
}

impl Subvol {
    fn label(&self) -> String {
        if self.id == FS_TREE {
            "the top level (id 5)".into()
        } else {
            format!("`{}` (id {})", self.name, self.id)
        }
    }
}

/// An opened Btrfs filesystem, presented as the tree its system mounts (see the module
/// documentation).
pub struct Btrfs<R> {
    image: R,
    chunks: Chunks,
    sectorsize: usize,
    nodesize: usize,
    block_id: [u8; 16],
    /// Every subvolume, the one read as `/` first.
    subvols: Vec<Subvol>,
    slots: HashMap<u64, usize>,
    /// The default subvolume's id: what a mount with no `subvol` option shows.
    default: u64,
    /// Mount points from `/etc/fstab` (no leading slash) and the subvolume slot mounted there.
    mounts: Vec<(String, usize)>,
    /// What the walk reports before it starts.
    notes: Vec<String>,
    decompress: Option<Box<dyn Decompress + Send>>,
}

/// A node's inode number: subvolume slot and inode number, if the inode number fits.
fn encode(slot: usize, ino: u64) -> Option<u64> {
    (ino < 1 << INO_BITS).then_some((slot as u64) << INO_BITS | ino)
}

fn decode(v: u64) -> (usize, u64, bool) {
    (((v & !STUB) >> INO_BITS) as usize, v & ((1 << INO_BITS) - 1), v & STUB != 0)
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl<R: ReadAt> Btrfs<R> {
    /// Opens the filesystem and decides what its walk shows: reads the superblock, the chunk
    /// map, the subvolumes, the default subvolume and the root's `/etc/fstab`. `decompress`
    /// reads zlib and zstd extents; without it, files (and an `/etc/fstab`) stored that way
    /// cannot be read.
    pub fn open(image: R, decompress: Option<Box<dyn Decompress + Send>>) -> Result<Btrfs<R>> {
        let sb = {
            let img: &dyn ReadAt = &image;
            let mut first = None;
            let mut found = None;
            for at in SUPERS {
                let mut buf = vec![0u8; SUPER_SIZE];
                let parsed = img.read_at(at, &mut buf).map_err(Error::from).and_then(|()| parse_superblock(&buf, at));
                match parsed {
                    Ok(sb) => {
                        found = Some(sb);
                        break;
                    }
                    Err(e) => {
                        first.get_or_insert(e);
                    }
                }
            }
            match (found, first) {
                (Some(sb), _) => sb,
                (None, Some(e)) => return Err(e),
                (None, None) => return Err(Error::corrupt("no Btrfs superblock")),
            }
        };
        let mut chunks = Chunks::new(sb.devid, image.size());
        chunks.add_array(&sb.array)?;
        // The chunk tree, read through the bootstrap chunks, maps everything else.
        let listed = {
            let disk = Disk { img: &image, chunks: &chunks, nodesize: sb.nodesize, fsid: &sb.block_id };
            let mut items = Vec::new();
            let root = Root { bytenr: sb.chunk_root, level: sb.chunk_level, owner: Some(CHUNK_TREE) };
            let start = Key::new(FIRST_CHUNK_TREE_OBJECTID, tree::CHUNK_ITEM, 0);
            disk.scan(&mut Cache::new(), root, start, false, &mut |k, data| {
                if k.obj != FIRST_CHUNK_TREE_OBJECTID || k.ty != tree::CHUNK_ITEM {
                    return Ok(k.obj <= FIRST_CHUNK_TREE_OBJECTID);
                }
                items.push((k.off, data.to_vec()));
                Ok(items.len() <= tree::MAX_CHUNKS)
            })?;
            items
        };
        for (logical, data) in listed {
            chunks.add(logical, &data)?;
        }
        let mut fs = Btrfs {
            image,
            chunks,
            sectorsize: sb.sectorsize,
            nodesize: sb.nodesize,
            block_id: sb.block_id,
            subvols: Vec::new(),
            slots: HashMap::new(),
            default: FS_TREE,
            mounts: Vec::new(),
            notes: Vec::new(),
            decompress,
        };
        let root_tree = Root { bytenr: sb.root, level: sb.root_level, owner: Some(ROOT_TREE) };
        let mut cache = Cache::new();
        fs.load_subvolumes(&mut cache, root_tree)?;
        fs.choose_root(&mut cache, root_tree)?;
        fs.read_fstab(&mut cache, &sb);

        let profiles = fs.chunks.unreadable_profiles();
        if !profiles.is_empty() {
            fs.notes.push(format!(
                "block groups not read ({}): files stored there are listed but cannot be read",
                profiles.join(", ")
            ));
        }
        if sb.num_devices > 1 {
            fs.notes.push(format!(
                "this is one device of a {}-device filesystem: only copies on this device are read",
                sb.num_devices
            ));
        }
        if sb.log_root != 0 {
            fs.notes.push("the log tree (writes synced since the last commit) is not replayed".into());
        }
        Ok(fs)
    }

    fn disk(&self) -> Disk<'_> {
        Disk { img: &self.image, chunks: &self.chunks, nodesize: self.nodesize, fsid: &self.block_id }
    }

    /// Lists the subvolumes from their root items and back references in the root tree.
    fn load_subvolumes(&mut self, cache: &mut Cache, root_tree: Root) -> Result<()> {
        let mut found: Vec<Subvol> = Vec::new();
        let mut names: HashMap<u64, (u64, String)> = HashMap::new();
        let mut more = false;
        let disk = self.disk();
        disk.scan(cache, root_tree, Key::new(FS_TREE, 0, 0), false, &mut |k, data| {
            if k.obj > LAST_FREE {
                return Ok(false);
            }
            if k.obj != FS_TREE && k.obj < FIRST_FREE {
                return Ok(true);
            }
            match k.ty {
                ROOT_ITEM => {
                    let Some(item) = items::root_item(data) else { return Ok(true) };
                    if item.refs == 0 || item.level > MAX_LEVEL {
                        return Ok(true);
                    }
                    let sub = Subvol {
                        id: k.obj,
                        root: Root { bytenr: item.bytenr, level: item.level, owner: None },
                        dirid: item.root_dirid,
                        readonly: item.readonly,
                        name: String::new(),
                        parent: 0,
                    };
                    // A tree has one root item; a later one for the same id replaces it.
                    if found.last().is_some_and(|last| last.id == k.obj) {
                        found.pop();
                    }
                    if found.len() >= MAX_SUBVOLUMES {
                        more = true;
                    } else {
                        found.push(sub);
                    }
                }
                ROOT_BACKREF => {
                    if let Some((_, name)) = items::root_ref(data) {
                        names.insert(k.obj, (k.off, String::from_utf8_lossy(name).into_owned()));
                    }
                }
                _ => {}
            }
            Ok(true)
        })?;
        if more {
            self.notes.push(format!("more than {MAX_SUBVOLUMES} subvolumes: the rest are not read"));
        }
        for sub in &mut found {
            if let Some((parent, name)) = names.remove(&sub.id) {
                sub.parent = parent;
                sub.name = name;
            }
        }
        if !found.iter().any(|s| s.id == FS_TREE) {
            return Err(Error::corrupt("no top-level subvolume"));
        }
        self.subvols = found;
        Ok(())
    }

    fn renumber(&mut self) {
        self.slots = self.subvols.iter().enumerate().map(|(i, s)| (s.id, i)).collect();
    }

    /// Picks the subvolume read as `/` and moves it to slot 0.
    fn choose_root(&mut self, cache: &mut Cache, root_tree: Root) -> Result<()> {
        self.renumber();
        // The root tree's directory 6 holds `default`, naming the default subvolume.
        let mut default = FS_TREE;
        let hash = u64::from(items::name_hash(b"default"));
        if let Some(item) = self.disk().get(cache, root_tree, Key::new(6, DIR_ITEM, hash))? {
            items::dir_entries(&item, &mut |loc, name| {
                if name == b"default" {
                    default = loc.obj;
                }
                name != b"default"
            });
        }
        self.default = default;
        let mut chosen = match self.slots.get(&default) {
            Some(&slot) => slot,
            None => {
                self.notes.push(format!("the default subvolume {default} does not exist: the top level is read as /"));
                self.slots[&FS_TREE]
            }
        };
        if self.subvols[chosen].id == FS_TREE && !self.has_etc(cache, chosen) {
            let mut best: Option<(u8, u64, usize)> = None;
            for (slot, s) in self.subvols.iter().enumerate() {
                if s.parent != FS_TREE || s.readonly || s.id == FS_TREE || !self.has_etc(cache, slot) {
                    continue;
                }
                let rank = match s.name.as_str() {
                    "@" => 0,
                    "root" => 1,
                    _ => 2,
                };
                if best.is_none_or(|b| (rank, s.id) < (b.0, b.1)) {
                    best = Some((rank, s.id, slot));
                }
            }
            if let Some((_, _, slot)) = best {
                self.notes.push(format!(
                    "the default subvolume is the top level, which has no /etc: subvolume {} is read as /",
                    self.subvols[slot].label()
                ));
                chosen = slot;
            }
        } else if self.subvols[chosen].id != FS_TREE {
            self.notes.push(format!("the default subvolume {} is read as /", self.subvols[chosen].label()));
        }
        self.subvols.swap(0, chosen);
        self.renumber();
        Ok(())
    }

    fn has_etc(&self, cache: &mut Cache, slot: usize) -> bool {
        let sub = &self.subvols[slot];
        matches!(self.lookup(cache, slot, sub.dirid, b"etc"), Ok(Some(loc)) if loc.ty == INODE_ITEM)
    }

    /// The location key of entry `name` of directory `dir`, through its hashed `DIR_ITEM`.
    fn lookup(&self, cache: &mut Cache, slot: usize, dir: u64, name: &[u8]) -> Result<Option<Key>> {
        let root = self.subvols[slot].root;
        let key = Key::new(dir, DIR_ITEM, u64::from(items::name_hash(name)));
        let Some(item) = self.disk().get(cache, root, key)? else { return Ok(None) };
        let mut found = None;
        items::dir_entries(&item, &mut |loc, entry| {
            if entry == name {
                found = Some(loc);
            }
            found.is_none()
        });
        Ok(found)
    }

    /// Follows `path` from the top directory of subvolume `slot`, into nested subvolumes.
    /// Returns the slot and inode reached, and whether it is a subvolume's top directory.
    fn resolve(&self, cache: &mut Cache, slot: usize, path: &str) -> Result<Option<(usize, u64, bool)>> {
        let (mut slot, mut ino, mut top) = (slot, self.subvols[slot].dirid, true);
        for name in path.split('/').filter(|c| !c.is_empty()) {
            let Some(loc) = self.lookup(cache, slot, ino, name.as_bytes())? else { return Ok(None) };
            match loc.ty {
                INODE_ITEM => (ino, top) = (loc.obj, false),
                ROOT_ITEM => match self.slots.get(&loc.obj) {
                    Some(&s) => (slot, ino, top) = (s, self.subvols[s].dirid, true),
                    None => return Ok(None),
                },
                _ => return Ok(None),
            }
        }
        Ok(Some((slot, ino, top)))
    }

    /// Reads `/etc/fstab` of the root and records the subvolumes it mounts.
    fn read_fstab(&mut self, cache: &mut Cache, sb: &Super) {
        let text = match self.fstab(cache) {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(e) => {
                self.notes.push(format!("/etc/fstab not read: {e}"));
                return;
            }
        };
        let uuid = uuid_string(&sb.uuid);
        let default = self.default;
        let mut mounted = Vec::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [spec, point, fstype, options, ..] = fields[..] else { continue };
            if spec.starts_with('#') || fstype != "btrfs" {
                continue;
            }
            let other = match spec.split_once('=') {
                Some(("UUID", u)) => !u.eq_ignore_ascii_case(&uuid),
                Some(("LABEL", l)) => l != sb.label,
                _ => false,
            };
            let point = unescape(point);
            let parts: Vec<&str> = point.split('/').filter(|c| !c.is_empty()).collect();
            if other || parts.is_empty() || parts.iter().any(|c| *c == "." || *c == "..") {
                continue;
            }
            let point = parts.join("/");
            let (mut by_id, mut by_path) = (None, None);
            for option in options.split(',') {
                match option.split_once('=') {
                    Some(("subvolid", id)) => by_id = id.parse::<u64>().ok(),
                    Some(("subvol", path)) => by_path = Some(unescape(path)),
                    _ => {}
                }
            }
            let target = match (by_id, &by_path) {
                (Some(id), _) => self.slots.get(&id).copied(),
                (None, Some(path)) => match self.resolve(cache, self.slots[&FS_TREE], path) {
                    Ok(Some((slot, _, true))) => Some(slot),
                    _ => None,
                },
                (None, None) => self.slots.get(&default).copied(),
            };
            let Some(slot) = target else {
                let what =
                    by_path.map_or_else(|| format!("subvolid={}", by_id.unwrap_or(0)), |p| format!("subvol={p}"));
                self.notes.push(format!("/etc/fstab: {what} for /{point} is not a subvolume here; not shown"));
                continue;
            };
            if slot == 0 || self.mounts.iter().any(|(p, s)| *p == point || *s == slot) {
                continue;
            }
            if self.mounts.len() >= MAX_MOUNTS {
                break;
            }
            mounted.push(format!("/{point} = {}", self.subvols[slot].label()));
            self.mounts.push((point, slot));
        }
        if !mounted.is_empty() {
            self.notes.push(format!("subvolumes shown where /etc/fstab mounts them: {}", mounted.join(", ")));
        }
    }

    fn fstab(&self, cache: &mut Cache) -> Result<Option<String>> {
        let Some((slot, ino, _)) = self.resolve(cache, 0, "etc/fstab")? else { return Ok(None) };
        let inode = self.inode(cache, slot, ino)?;
        if kind(inode.mode) != Kind::File || inode.size > MAX_FSTAB {
            return Err(Error::corrupt("not a regular file of reasonable size"));
        }
        let mut buf = vec![0u8; inode.size as usize];
        let n = self.read_file(cache, slot, ino, &inode, 0, &mut buf)?;
        buf.truncate(n);
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }

    fn inode(&self, cache: &mut Cache, slot: usize, ino: u64) -> Result<Inode> {
        let root = self.subvols.get(slot).ok_or_else(|| Error::corrupt(format!("no subvolume slot {slot}")))?.root;
        let item = self.disk().get(cache, root, Key::new(ino, INODE_ITEM, 0))?;
        item.as_deref().and_then(items::inode).ok_or_else(|| Error::corrupt(format!("inode {ino} not found")))
    }

    fn decompress(&self, compression: u8, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
        let kind = match compression {
            items::COMPRESS_LZO => return lzo::decompress(input, self.sectorsize, out, limit),
            items::COMPRESS_ZLIB => Compression::Zlib,
            items::COMPRESS_ZSTD => Compression::Zstd,
            c => return Err(Error::unsupported(format!("compression type {c}"))),
        };
        match &self.decompress {
            Some(d) => d.decompress(kind, input, out, limit),
            None => Err(Error::unsupported(format!("{kind:?}-compressed data: no decompressor"))),
        }
    }

    /// Fills `buf` (zeroed by the caller) with the part of one file extent, at file offset
    /// `at`, that overlaps the file range starting at `offset`.
    fn copy_extent(&self, at: u64, item: &[u8], offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset + buf.len() as u64;
        let bad = |what: &str| Error::corrupt(format!("file extent at {at}: {what}"));
        // Copies `data`, which holds the file from `at`, into the overlap.
        let put = |buf: &mut [u8], data: &[u8]| {
            let (from, to) = (at.max(offset), at.saturating_add(data.len() as u64).min(end));
            if from < to {
                buf[(from - offset) as usize..(to - offset) as usize]
                    .copy_from_slice(&data[(from - at) as usize..(to - at) as usize]);
            }
        };
        match items::extent(item).ok_or_else(|| bad("malformed"))? {
            items::Extent::Encoded => Err(Error::unsupported("encrypted or encoded file extent")),
            items::Extent::Inline { compression: items::COMPRESS_NONE, data, .. } => {
                put(buf, data);
                Ok(())
            }
            items::Extent::Inline { compression, data, ram } => {
                let mut out = Vec::new();
                self.decompress(compression, data, &mut out, ram.min(MAX_EXTENT) as usize)?;
                put(buf, &out);
                Ok(())
            }
            items::Extent::Regular { compression, disk, disk_len, offset: inside, len, ram, prealloc } => {
                if prealloc || disk == 0 {
                    return Ok(());
                }
                let (from, to) = (at.max(offset), at.saturating_add(len).min(end));
                if from >= to {
                    return Ok(());
                }
                if inside.checked_add(len).is_none_or(|e| e > ram) {
                    return Err(bad("range outside its extent"));
                }
                let dst = &mut buf[(from - offset) as usize..(to - offset) as usize];
                let skip = inside + (from - at);
                if compression == items::COMPRESS_NONE {
                    let logical = disk.checked_add(skip).ok_or_else(|| bad("address overflows"))?;
                    return self.chunks.read(&self.image, logical, dst);
                }
                if disk_len > MAX_EXTENT || ram > MAX_EXTENT {
                    return Err(bad("compressed extent larger than 128 KiB"));
                }
                let mut input = vec![0u8; disk_len as usize];
                self.chunks.read(&self.image, disk, &mut input)?;
                let mut out = Vec::new();
                self.decompress(compression, &input, &mut out, ram as usize)?;
                // Bytes the stream did not produce read as zeros.
                let src = out.get(skip as usize..).unwrap_or(&[]);
                let n = src.len().min(dst.len());
                dst[..n].copy_from_slice(&src[..n]);
                Ok(())
            }
        }
    }

    /// Reads file content: extents at or before `offset`, up to the file size.
    fn read_file(
        &self,
        cache: &mut Cache,
        slot: usize,
        ino: u64,
        inode: &Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        let n = buf.len().min(usize::try_from(inode.size - offset).unwrap_or(usize::MAX));
        let buf = &mut buf[..n];
        buf.fill(0);
        let end = offset + n as u64;
        let root = self.subvols[slot].root;
        self.disk().scan(cache, root, Key::new(ino, EXTENT_DATA, offset), true, &mut |k, item| {
            if k.obj < ino || (k.obj == ino && k.ty < EXTENT_DATA) {
                return Ok(true);
            }
            if k.obj != ino || k.ty != EXTENT_DATA || k.off >= end {
                return Ok(false);
            }
            self.copy_extent(k.off, item, offset, buf)?;
            Ok(true)
        })?;
        Ok(n)
    }

    fn symlink(&self, cache: &mut Cache, slot: usize, ino: u64, inode: &Inode) -> Result<Vec<u8>> {
        if inode.size > MAX_SYMLINK {
            return Err(Error::corrupt(format!("symlink of {} bytes", inode.size)));
        }
        let mut target = vec![0u8; inode.size as usize];
        let n = self.read_file(cache, slot, ino, inode, 0, &mut target)?;
        target.truncate(n);
        Ok(target)
    }

    fn node(&self, cache: &mut Cache, id: u64) -> Result<Node> {
        let (slot, ino, _) = decode(id);
        let inode = self.inode(cache, slot, ino)?;
        let kind = kind(inode.mode);
        let link_target = match kind {
            Kind::Symlink => Some(String::from_utf8_lossy(&self.symlink(cache, slot, ino, &inode)?).into_owned()),
            _ => None,
        };
        Ok(Node {
            path: String::new(),
            inode: id & !STUB,
            kind,
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            allocated: inode.nbytes,
            links: inode.nlink,
            accessed: inode.atime,
            modified: inode.mtime,
            changed: inode.ctime,
            created: inode.otime,
            link_target,
        })
    }
}

/// An fstab field with its octal escapes (`\040` for a space) decoded.
fn unescape(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b.get(i + 1..i + 4).filter(|d| d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match (b[i], octal) {
            (b'\\', Some(d)) => {
                out.push(d.iter().fold(0u8, |v, c| v.wrapping_mul(8).wrapping_add(c - b'0')));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Per-walk state.
struct Walker<'w, R> {
    fs: &'w Btrfs<R>,
    cache: Cache,
    /// Subvolumes walked or to be walked where they are mounted.
    claimed: Vec<bool>,
    /// Mount points by path, and the directories that hold them.
    mounts: HashMap<&'w str, usize>,
    holders: HashSet<&'w str>,
    reached: HashSet<usize>,
    snapshots: Vec<String>,
}

impl<R: ReadAt> crate::Tree for Walker<'_, R> {
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let (slot, ino, stub) = decode(dir);
        if stub {
            return Ok(());
        }
        let fs = self.fs;
        let holder = self.holders.contains(path);
        let (mut bad, mut missing, mut large) = (0usize, 0usize, 0usize);
        let mut placed = Vec::new();
        let Walker { cache, claimed, mounts, snapshots, reached, .. } = self;
        let root = fs.subvols.get(slot).ok_or_else(|| Error::corrupt(format!("no subvolume slot {slot}")))?.root;
        let scanned = fs.disk().scan(cache, root, Key::new(ino, DIR_INDEX, 0), false, &mut |k, item| {
            if k.obj != ino || k.ty != DIR_INDEX {
                return Ok(false);
            }
            let mut room = true;
            let whole = items::dir_entries(item, &mut |loc, name| {
                let mounted = if holder {
                    mounts.get(join(path, &String::from_utf8_lossy(name)).as_str()).copied()
                } else {
                    None
                };
                let child = if let Some(m) = mounted {
                    placed.push(m);
                    encode(m, fs.subvols[m].dirid)
                } else {
                    match loc.ty {
                        INODE_ITEM => encode(slot, loc.obj),
                        ROOT_ITEM => match fs.slots.get(&loc.obj) {
                            None => {
                                missing += 1;
                                return true;
                            }
                            Some(&s) => {
                                let sub = &fs.subvols[s];
                                let base = encode(s, sub.dirid);
                                if claimed[s] || sub.readonly {
                                    if sub.readonly && !claimed[s] && snapshots.len() < 1 << 20 {
                                        snapshots.push(join(path, &String::from_utf8_lossy(name)));
                                    }
                                    base.map(|b| b | STUB)
                                } else {
                                    claimed[s] = true;
                                    base
                                }
                            }
                        },
                        _ => {
                            bad += 1;
                            return true;
                        }
                    }
                };
                match child {
                    Some(child) => room = out.push(child, name),
                    None => large += 1,
                }
                room
            });
            if !whole {
                bad += 1;
            }
            Ok(room)
        });
        if holder {
            // Mount points the root has no directory for still show the mounted subvolume.
            for (&point, &m) in mounts.iter() {
                let (parent, name) = point.rsplit_once('/').unwrap_or(("", point));
                if parent == path && !placed.contains(&m) {
                    if let Some(child) = encode(m, fs.subvols[m].dirid) {
                        out.push(child, name.as_bytes());
                        placed.push(m);
                    }
                }
            }
            reached.extend(placed);
        }
        for (count, what) in [
            (bad, "malformed directory entries"),
            (missing, "entries for subvolumes that no longer exist"),
            (large, "entries with inode numbers above 2^48"),
        ] {
            if count > 0 {
                warn(format!("{}: {count} {what} skipped", shown(path)));
            }
        }
        scanned
    }

    fn node(&mut self, ino: u64, _path: &str, _warn: &mut dyn FnMut(String)) -> Result<Node> {
        self.fs.node(&mut self.cache, ino)
    }

    fn exhausted(&self) -> bool {
        self.cache.exhausted()
    }
}

/// `names` as a warning lists them: the first few, then a count.
fn listed(names: &[String]) -> String {
    let mut text = names.iter().take(NAMES_SHOWN).map(|n| format!("/{n}")).collect::<Vec<_>>().join(", ");
    if names.len() > NAMES_SHOWN {
        text.push_str(&format!(" and {} more", names.len() - NAMES_SHOWN));
    }
    text
}

impl<R: ReadAt> Volume for Btrfs<R> {
    fn kind(&self) -> &'static str {
        "btrfs"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        for note in &self.notes {
            warn(format!("btrfs: {note}"));
        }
        let mut claimed = vec![false; self.subvols.len()];
        claimed[0] = true;
        for &(_, slot) in &self.mounts {
            claimed[slot] = true;
        }
        let mut walker = Walker {
            fs: self,
            cache: Cache::new(),
            claimed,
            mounts: self.mounts.iter().map(|(p, s)| (p.as_str(), *s)).collect(),
            holders: self.mounts.iter().map(|(p, _)| p.rsplit_once('/').map_or("", |(parent, _)| parent)).collect(),
            reached: HashSet::new(),
            snapshots: Vec::new(),
        };
        let root =
            encode(0, self.subvols[0].dirid).ok_or_else(|| Error::corrupt("root directory inode out of range"))?;
        let walked = walk_tree("btrfs", &mut walker, root, visit, warn);
        let Walker { claimed, reached, snapshots, .. } = walker;
        if !snapshots.is_empty() {
            warn(format!(
                "btrfs: {} read-only snapshots not walked (listed as empty directories): {}",
                snapshots.len(),
                listed(&snapshots)
            ));
        }
        let unreached: Vec<String> =
            self.mounts.iter().filter(|(_, s)| !reached.contains(s)).map(|(p, _)| p.clone()).collect();
        if !unreached.is_empty() {
            warn(format!("btrfs: /etc/fstab mount points not reached, not walked: {}", listed(&unreached)));
        }
        let unwalked: Vec<String> = self
            .subvols
            .iter()
            .zip(&claimed)
            .filter(|(s, &c)| !c && !s.readonly && s.id != FS_TREE)
            .map(|(s, _)| s.label())
            .collect();
        if !unwalked.is_empty() {
            let names = unwalked.iter().take(NAMES_SHOWN).cloned().collect::<Vec<_>>().join(", ");
            warn(format!(
                "btrfs: {} subvolumes neither under / nor mounted by /etc/fstab, not walked: {names}{}",
                unwalked.len(),
                if unwalked.len() > NAMES_SHOWN { " and more" } else { "" }
            ));
        }
        walked
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (slot, ino, _) = decode(inode);
        let mut cache = Cache::new();
        let found = self.inode(&mut cache, slot, ino)?;
        match kind(found.mode) {
            Kind::File => self.read_file(&mut cache, slot, ino, &found, offset, buf),
            Kind::Symlink => {
                let target = self.symlink(&mut cache, slot, ino, &found)?;
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(target.len());
                let n = buf.len().min(target.len() - start);
                buf[..n].copy_from_slice(&target[start..start + n]);
                Ok(n)
            }
            Kind::Directory => Err(Error::unsupported("a directory has no content to read")),
            Kind::Other => Err(Error::unsupported("device, socket or FIFO has no content")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_numbers_round_trip() {
        assert_eq!(encode(0, 257), Some(257));
        let id = encode(3, 300).unwrap();
        assert_eq!(decode(id), (3, 300, false));
        assert_eq!(decode(id | STUB), (3, 300, true));
        assert_eq!(encode(1, 1 << 48), None);
        assert_eq!(
            decode(encode(MAX_SUBVOLUMES - 1, (1 << 48) - 1).unwrap()),
            (MAX_SUBVOLUMES - 1, (1 << 48) - 1, false)
        );
    }

    #[test]
    fn colliding_names_share_one_dir_item() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/btrfs");
        let data = zstd::decode_all(std::fs::File::open(dir.join("default.img.zst")).unwrap()).unwrap();
        let names = std::fs::read_to_string(dir.join("default.collision")).unwrap();
        let (a, b) = names.trim().split_once('\n').unwrap();
        let hash = items::name_hash(a.as_bytes());
        assert_eq!(hash, items::name_hash(b.as_bytes()));
        let fs = Btrfs::open(crate::Bytes(&data), None).unwrap();
        let mut cache = Cache::new();
        let (slot, dir, _) = fs.resolve(&mut cache, 0, "collide").unwrap().unwrap();
        let item = fs.disk().get(&mut cache, fs.subvols[slot].root, Key::new(dir, DIR_ITEM, u64::from(hash)));
        let mut count = 0;
        assert!(items::dir_entries(&item.unwrap().unwrap(), &mut |_, _| {
            count += 1;
            true
        }));
        assert_eq!(count, 2);
        let first = fs.lookup(&mut cache, slot, dir, a.as_bytes()).unwrap().unwrap();
        let second = fs.lookup(&mut cache, slot, dir, b.as_bytes()).unwrap().unwrap();
        assert_ne!(first.obj, second.obj);
        assert_eq!(fs.lookup(&mut cache, slot, dir, b"collide-none").unwrap(), None);
    }

    #[test]
    fn fstab_escapes() {
        assert_eq!(unescape(r"/mnt/with\040space"), "/mnt/with space");
        assert_eq!(unescape(r"a\0"), r"a\0");
        assert_eq!(unescape(r"\777"), "\u{fffd}");
    }
}

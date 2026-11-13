//! ZFS, read-only.
//!
//! Written from the OpenZFS sources (`include/sys/fs/zfs.h`, `uberblock_impl.h`, `spa.h`,
//! `dmu.h`, `dnode.h`, `zap_impl.h`, `zap_leaf.h`, `zfs_znode.h`, `sa_impl.h`,
//! `dsl_dataset.h`, `dsl_dir.h`, `vdev_impl.h`, `vdev_raidz.c`) and the "ZFS On-Disk
//! Specification". Each block carries its own byte order in its block pointer; both orders
//! are read.
//!
//! Supported:
//! - the four vdev labels of every device given (the partitions of one image that hold
//!   members of the pool), their name-value lists and uberblock rings: the uberblock with the
//!   highest transaction group whose meta object set reads is used. Checksums are NOT
//!   verified; structure is (block types, levels, sizes, magic numbers);
//! - single-device, mirror (any present child), striped (every top-level vdev present) and
//!   RAID-Z1/2/3 (every data column present; parity is never read, nothing is
//!   reconstructed) top-level vdevs; every copy of a block (ditto blocks) is tried in turn;
//!   gang blocks; embedded block pointers; holes;
//! - lz4, lzjb and zle decompression here; gzip-1 to 9 and zstd through the [`Decompress`]
//!   the volume is given (without one, such a block is an `Unsupported` read error);
//! - the meta object set, the dataset hierarchy (DSL directories and their property ZAPs),
//!   object sets, dnodes of any size (`large_dnode`), indirect block trees, micro and fat
//!   ZAPs, file attributes as system attributes (bonus buffer and spill block) or as the
//!   older `znode_phys_t`, symlinks in the attributes or in the file data.
//!
//! What a walk shows is the tree the installed system mounts:
//! - `/` is the dataset the pool's `bootfs` property names; without one, the dataset whose
//!   `mountpoint` is `/` and whose `canmount` is not `off` (`on` first, then the one written
//!   last); without one, a dataset with `mountpoint=legacy` or `none` holding `etc` at its
//!   top (a root an initramfs mounts). Without any, `/` is an empty
//!   directory and every dataset is where its mountpoint puts it (`/tank`, `/tank/home`).
//! - Every other file system dataset with `canmount=on` is shown at its `mountpoint`
//!   (inherited ones extended by the dataset's own name, as `zfs` does); one with
//!   `mountpoint=legacy` where the root's `/etc/fstab` mounts it with type `zfs`. Directories
//!   a mountpoint needs that no dataset has are shown as empty directories.
//! - Boot environments other than the root (children of `<pool>/ROOT`) are not walked, nor
//!   anything under them; datasets with `canmount=off` or `noauto` or `mountpoint=none` are
//!   not mounted. Each group is named in one warning. No dataset is walked twice.
//! - Snapshots are counted in a warning, never walked; clones are datasets like any other.
//!   Volumes (zvols) are named in a warning, not read. A natively encrypted dataset is named
//!   in a warning and not mounted: what is under its mountpoint shows, as on a system that
//!   has not loaded its key.
//!
//! Node inode numbers: the low 48 bits are the object number in its dataset and bits 48 to
//! 62 the dataset's slot (0 for the dataset read as `/`, so its files carry their own inode
//! numbers); bit 63 marks a dataset shown as an empty directory. Slot 0x7fff holds the
//! directories made up for mountpoints.
//!
//! Not supported: checksum verification, the intent log (not replayed: a warning names the
//! datasets that have one), dRAID, RAID-Z expansion and removed (indirect) vdevs (refused
//! through their read features, or a read error naming the vdev), reconstruction from parity
//! or of a missing mirror side, native encryption, extended attributes, ACLs, snapshots,
//! bookmarks, zvol contents, case-insensitive name lookup (names are listed as stored),
//! pools written by a big-endian host are read but were tested only with synthetic blocks.

mod block;
mod compress;
mod label;
mod zap;
mod zpl;

use std::collections::{BTreeMap, HashMap, HashSet};

use block::{u64e, Bp, Cache, Dnode, Pool, Vdev, DNODE_SIZE, OT_OBJSET};
use label::NvList;
use zpl::{Sa, Znode};

use crate::btrfs::Decompress;
use crate::{shown, walk_tree, Entries, Error, Kind, Node, ReadAt, Result, Volume};

/// Read features the reader handles. A pool with another one active is refused, naming it.
const KNOWN_FEATURES: &[&str] = &[
    "com.delphix:hole_birth",
    "com.delphix:embedded_data",
    "com.delphix:extensible_dataset",
    "com.delphix:bookmarks",
    "com.datto:bookmark_v2",
    "com.delphix:bookmark_written",
    "com.delphix:head_errlog",
    "com.datto:encryption",
    "com.joyent:multi_vdev_crash_dump",
    "com.delphix:zpool_checkpoint",
    "com.fudosecurity:block_cloning",
    "com.klarasystems:vdev_zaps_v2",
    "com.klarasystems:fast_dedup",
    "org.illumos:lz4_compress",
    "org.illumos:sha512",
    "org.illumos:skein",
    "org.illumos:edonr",
    "org.openzfs:blake3",
    "org.freebsd:zstd_compress",
    "org.open-zfs:large_blocks",
    "org.openzfs:large_microzap",
    "org.zfsonlinux:large_dnode",
    "org.openzfs:longname",
];

/// Datasets read: the slot must fit 15 bits of a node's inode number, and one is reserved.
const MAX_DATASETS: usize = 1 << 14;
const SYNTH: usize = 0x7fff;
const INO_BITS: u32 = 48;
const STUB: u64 = 1 << 63;
const MAX_SYMLINK: u64 = 4095;
const MAX_FSTAB: u64 = 1 << 20;
/// Paths and names a warning lists before it only counts.
const NAMES_SHOWN: usize = 10;
/// Uberblocks tried, best first, before the pool is given up.
const MAX_UBERBLOCKS: usize = 16;

/// `DMU_OT_PLAIN_FILE_CONTENTS`: a file's dnode, which is no directory.
const OT_PLAIN_FILE: u8 = 19;
const OST_ZFS: u64 = 2;
const OST_ZVOL: u64 = 3;
const S_IFMT: u64 = 0o170000;

fn kind(mode: u64) -> Kind {
    match mode & S_IFMT {
        0o100000 => Kind::File,
        0o040000 => Kind::Directory,
        0o120000 => Kind::Symlink,
        _ => Kind::Other,
    }
}

/// Recognizes a ZFS vdev label at the start of `dev`.
pub fn probe(dev: &dyn ReadAt) -> bool {
    label::probe(dev)
}

/// The pool guid and this device's guid, from its label: what tells members of one pool
/// apart from those of another.
pub fn member(dev: &dyn ReadAt) -> Option<(u64, u64)> {
    let config = label::config(dev)?;
    Some((config.u64("pool_guid")?, config.u64("guid")?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mount {
    Path(String),
    Legacy,
    None,
}

/// An opened file system dataset.
struct Fs {
    meta: Dnode,
    root: u64,
    sa: Option<Sa>,
}

struct Dataset {
    name: String,
    ds_obj: u64,
    mountpoint: Mount,
    /// 0 off, 1 on, 2 noauto.
    canmount: u64,
    encrypted: bool,
    os_type: u64,
    /// When it was last written: the birth of its object set.
    birth: u64,
    snapshots: u64,
    has_log: bool,
    fs: Option<Fs>,
}

/// An opened pool, presented as the tree its system mounts (see the module documentation).
pub struct Zfs<R> {
    pool: Pool<R>,
    datasets: Vec<Dataset>,
    root: Option<usize>,
    /// Mount points (no leading slash) and the dataset slot shown there.
    mounts: Vec<(String, usize)>,
    notes: Vec<String>,
}

fn encode(slot: usize, obj: u64) -> Option<u64> {
    (obj < 1 << INO_BITS).then_some((slot as u64) << INO_BITS | obj)
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

/// `names` as a warning lists them: the first few, then a count.
fn listed(names: &[String]) -> String {
    let mut text = names.iter().take(NAMES_SHOWN).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > NAMES_SHOWN {
        text.push_str(&format!(" and {} more", names.len() - NAMES_SHOWN));
    }
    text
}

/// Reads object `obj` of the object set whose meta dnode is `meta`.
fn dnode<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, meta: &Dnode, obj: u64) -> Result<Dnode> {
    let at = obj.checked_mul(DNODE_SIZE as u64).ok_or_else(|| Error::corrupt(format!("object {obj} out of range")))?;
    let bs = meta.datablksz;
    let (blkid, within) = (at / bs, (at % bs) as usize);
    let block = meta.block(pool, cache, blkid)?.ok_or_else(|| Error::corrupt(format!("object {obj} is free")))?;
    let slots = 1 + usize::from(block.data.get(within + 12).copied().unwrap_or(0));
    let b = block.data.get(within..within + slots * DNODE_SIZE);
    let b = b.ok_or_else(|| Error::corrupt(format!("object {obj}: dnode past the end of its block")))?;
    Dnode::parse(b, block.le).map_err(|e| match e {
        Error::Corrupt(m) => Error::corrupt(format!("object {obj}: {m}")),
        e => e,
    })
}

/// An object set's meta dnode, type and whether its intent log holds blocks.
fn objset<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, bp: &Bp) -> Result<(Dnode, u64, bool)> {
    if bp.kind() != OT_OBJSET || bp.level() != 0 {
        return Err(Error::corrupt("object set block pointer of another type"));
    }
    let block = pool.read(cache, bp)?;
    let (b, le) = (&block.data, block.le);
    if b.len() < 1024 {
        return Err(Error::corrupt("object set block too short"));
    }
    let meta = Dnode::parse(&b[..DNODE_SIZE], le)?;
    // The intent log header: claim txg, replay sequence, first log block.
    let has_log = u64e(b, 512, le) != 0 || zil_has_records(pool, cache, &Bp::parse(b, 528, le));
    Ok((meta, u64e(b, 704, le), has_log))
}

/// Whether the first block of an intent log holds records: it reads and links to a next
/// block whose checksum verifier is this one's with the sequence number one higher, as
/// `zil_read_log_block` requires. After a clean close the header still points at an
/// allocated block, but nothing valid was written there. A block that cannot be read (on a
/// log device missing from the image, which a warning names) does not count.
fn zil_has_records<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, bp: &Bp) -> bool {
    if bp.hole() {
        return false;
    }
    let Ok(block) = pool.read(cache, bp) else { return false };
    let (b, le) = (&block.data, block.le);
    // `zil_chain_t` (pad, next block pointer, bytes used, embedded checksum): at the start of
    // a ZILOG2 block, at the end of an older ZILOG one.
    const CHAIN: usize = 184;
    let at = match bp.checksum() {
        9 => 0,
        _ => match b.len().checked_sub(CHAIN) {
            Some(at) => at,
            None => return false,
        },
    };
    let next = Bp::parse(b, at + 8, le);
    let mut expected = bp.cksum();
    expected[3] = expected[3].wrapping_add(1);
    !next.hole() && next.cksum() == expected
}

impl<R: ReadAt> Zfs<R> {
    /// Opens the pool whose members are `devices` (every one must carry a label of the same
    /// pool) and decides what its walk shows. `decompress` reads gzip and zstd blocks.
    pub fn open(devices: Vec<R>, decompress: Option<Box<dyn Decompress + Send>>) -> Result<Zfs<R>> {
        let mut notes = Vec::new();
        let configs: Vec<Option<NvList>> = devices.iter().map(|d| label::config(d)).collect();
        let first = configs.iter().flatten().next().ok_or_else(|| Error::corrupt("no readable ZFS label"))?;
        let pool_guid = first.u64("pool_guid").ok_or_else(|| Error::corrupt("label without a pool guid"))?;
        let pool_name = first.str("name").unwrap_or("").to_string();
        let version = first.u64("version").unwrap_or(0);
        if version == 0 || (version > 28 && version != 5000) {
            return Err(Error::unsupported(format!("ZFS pool version {version}")));
        }
        // Each device's own guid, and the newest description of each top-level vdev.
        let mut leaves = HashMap::new();
        let mut tops: BTreeMap<u64, (u64, NvList)> = BTreeMap::new();
        let mut children = 0;
        let mut features = HashSet::new();
        let mut ashifts = vec![9u64; devices.len()];
        for (i, config) in configs.iter().enumerate() {
            let Some(config) = config.as_ref().filter(|c| c.u64("pool_guid") == Some(pool_guid)) else { continue };
            if let Some(guid) = config.u64("guid") {
                leaves.entry(guid).or_insert(i);
            }
            children = children.max(config.u64("vdev_children").unwrap_or(1));
            if let Some(f) = config.list("features_for_read") {
                features.extend(f.0.iter().map(|(n, _)| n.clone()));
            }
            let txg = config.u64("txg").unwrap_or(0);
            if let Some(tree) = config.list("vdev_tree") {
                ashifts[i] = tree.u64("ashift").unwrap_or(9);
                let id = tree.u64("id").unwrap_or(0);
                if tops.get(&id).is_none_or(|(t, _)| *t < txg) {
                    tops.insert(id, (txg, tree.clone()));
                }
            }
        }
        if children > 256 {
            return Err(Error::corrupt(format!("{children} top-level vdevs")));
        }
        let mut top: Vec<Option<Vdev>> = vec![None; children as usize];
        let mut logs = 0;
        for (id, (_, tree)) in &tops {
            if let Some(slot) = top.get_mut(*id as usize) {
                *slot = Some(build_vdev(tree, &leaves, tree.u64("ashift").unwrap_or(9), 0));
                logs += usize::from(tree.u64("is_log") == Some(1));
            }
        }
        let mut missing = Vec::new();
        for (id, t) in top.iter().enumerate() {
            match t {
                None => missing.push(format!("top-level vdev {id}")),
                Some(v) => {
                    let mut guids = Vec::new();
                    v.missing(&mut guids);
                    missing.extend(guids.iter().map(|g| format!("vdev {g}")));
                }
            }
        }
        if !missing.is_empty() {
            notes.push(format!(
                "pool `{pool_name}`: {} not in the image; blocks stored only there cannot be read",
                listed(&missing)
            ));
        }
        if logs > 0 {
            notes.push(format!("pool `{pool_name}`: {logs} log vdevs; the intent log is not replayed"));
        }
        let pool = Pool { devices, top, decompress, shared: Default::default() };

        // The newest uberblock whose meta object set reads.
        let mut ubs: Vec<label::Uberblock> = Vec::new();
        for (dev, ashift) in pool.devices.iter().zip(&ashifts) {
            ubs.extend(label::uberblocks(dev, *ashift));
        }
        ubs.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
        ubs.dedup_by(|a, b| a.txg == b.txg && a.rootbp == b.rootbp);
        let mut cache = Cache::new();
        let mut mos = None;
        let mut first_error = None;
        for ub in ubs.iter().filter(|u| u.version > 0 && u.version <= 5000).take(MAX_UBERBLOCKS) {
            let bp = Bp::parse(&ub.rootbp, 0, ub.le);
            match objset(&pool, &mut cache, &bp) {
                Ok((meta, 1, _)) => {
                    mos = Some(meta);
                    break;
                }
                Ok((_, t, _)) => {
                    first_error.get_or_insert(Error::corrupt(format!("meta object set of type {t}")));
                }
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        let Some(mos) = mos else {
            return Err(first_error.unwrap_or_else(|| Error::corrupt("no uberblock")));
        };

        // The object directory names the root dataset, the read features and pool properties.
        let objdir = dnode(&pool, &mut cache, &mos, 1)?;
        let (mut root_dir, mut for_read, mut props) = (None, None, None);
        zap::list(&pool, &mut cache, &objdir, &mut |name, v| {
            match name {
                b"root_dataset" => root_dir = v.first(),
                b"features_for_read" => for_read = v.first(),
                b"pool_props" => props = v.first(),
                _ => {}
            }
            true
        })?;
        if let Some(obj) = for_read {
            let node = dnode(&pool, &mut cache, &mos, obj)?;
            zap::list(&pool, &mut cache, &node, &mut |name, v| {
                if v.first().unwrap_or(0) > 0 {
                    features.insert(String::from_utf8_lossy(name).into_owned());
                }
                features.len() < 4096
            })?;
        }
        let mut unknown: Vec<&String> = features.iter().filter(|f| !KNOWN_FEATURES.contains(&f.as_str())).collect();
        if !unknown.is_empty() {
            unknown.sort();
            let names = unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            return Err(Error::unsupported(format!("ZFS pool `{pool_name}` uses read features {names}")));
        }
        let mut bootfs = None;
        if let Some(obj) = props {
            let node = dnode(&pool, &mut cache, &mos, obj)?;
            bootfs = zap::lookup(&pool, &mut cache, &node, b"bootfs")?.and_then(|v| v.first());
        }
        let root_dir = root_dir.ok_or_else(|| Error::corrupt("no root dataset"))?;

        let mut fs = Zfs { pool, datasets: Vec::new(), root: None, mounts: Vec::new(), notes };
        fs.load_datasets(&mut cache, &mos, root_dir, &pool_name)?;
        fs.choose_root(&mut cache, bootfs, &pool_name);
        fs.plan_mounts(&mut cache, &pool_name);
        Ok(fs)
    }

    /// Lists the datasets from the root DSL directory down, with their effective mountpoint.
    fn load_datasets(&mut self, cache: &mut Cache, mos: &Dnode, root_dir: u64, pool_name: &str) -> Result<()> {
        let pool = &self.pool;
        let mut stack = vec![(root_dir, pool_name.to_string(), None::<Mount>)];
        let mut seen = HashSet::new();
        let (mut more, mut errors) = (false, Vec::new());
        while let Some((dir, name, parent)) = stack.pop() {
            if !seen.insert(dir) {
                continue;
            }
            if self.datasets.len() >= MAX_DATASETS {
                more = true;
                break;
            }
            let loaded = (|| -> Result<(Dataset, u64)> {
                let dd = dnode(pool, cache, mos, dir)?;
                let (b, le) = (&dd.bonus, dd.le);
                if b.len() < 96 {
                    return Err(Error::corrupt("DSL directory bonus too short"));
                }
                let (head, child_zap, props_zap) = (u64e(b, 8, le), u64e(b, 32, le), u64e(b, 80, le));
                let (mut mountpoint, mut recvd, mut canmount) = (None, None, 1);
                if props_zap != 0 {
                    let props = dnode(pool, cache, mos, props_zap)?;
                    zap::list(pool, cache, &props, &mut |n, v| {
                        match n {
                            b"mountpoint" => mountpoint = v.string(),
                            b"mountpoint$recvd" => recvd = v.string(),
                            b"canmount" => canmount = v.first().unwrap_or(1),
                            _ => {}
                        }
                        true
                    })?;
                }
                let last = name.rsplit('/').next().unwrap_or(&name);
                let mountpoint = match mountpoint.or(recvd).as_deref() {
                    Some("legacy") => Mount::Legacy,
                    Some("none") => Mount::None,
                    Some(p) if p.starts_with('/') => Mount::Path(p.trim_end_matches('/').to_string()),
                    Some(_) => Mount::None,
                    None => match &parent {
                        None => Mount::Path(format!("/{name}")),
                        Some(Mount::Path(p)) => Mount::Path(format!("{}/{last}", p.trim_end_matches('/'))),
                        Some(m) => m.clone(),
                    },
                };
                let ds = dnode(pool, cache, mos, head)?;
                let (b, le) = (&ds.bonus, ds.le);
                if b.len() < 256 {
                    return Err(Error::corrupt("dataset bonus too short"));
                }
                let bp = Bp::parse(b, 128, le);
                let snapnames = u64e(b, 32, le);
                let mut snapshots = 0;
                if snapnames != 0 {
                    if let Ok(node) = dnode(pool, cache, mos, snapnames) {
                        let _ = zap::list(pool, cache, &node, &mut |_, _| {
                            snapshots += 1;
                            snapshots < 1 << 20
                        });
                    }
                }
                let mut dataset = Dataset {
                    name: name.clone(),
                    ds_obj: head,
                    mountpoint,
                    canmount,
                    encrypted: bp.crypt(),
                    os_type: 0,
                    birth: bp.birth(),
                    snapshots,
                    has_log: false,
                    fs: None,
                };
                if !bp.hole() {
                    let (meta, os_type, has_log) = objset(pool, cache, &bp)?;
                    (dataset.os_type, dataset.has_log) = (os_type, has_log);
                    if os_type == OST_ZFS && !dataset.encrypted {
                        dataset.fs = Some(open_fs(pool, cache, meta)?);
                    }
                }
                Ok((dataset, child_zap))
            })();
            let (dataset, child_zap) = match loaded {
                Ok(found) => found,
                Err(e) => {
                    errors.push(format!("{name}: {e}"));
                    continue;
                }
            };
            let mountpoint = dataset.mountpoint.clone();
            self.datasets.push(dataset);
            if child_zap == 0 {
                continue;
            }
            let mut kids = Vec::new();
            let listed = dnode(pool, cache, mos, child_zap).and_then(|node| {
                zap::list(pool, cache, &node, &mut |n, v| {
                    // `$MOS`, `$FREE` and `$ORIGIN` are internal.
                    if let (false, Some(obj)) = (n.starts_with(b"$"), v.first()) {
                        kids.push((obj, format!("{name}/{}", String::from_utf8_lossy(n))));
                    }
                    kids.len() < MAX_DATASETS
                })
            });
            if let Err(e) = listed {
                errors.push(format!("{name}: children: {e}"));
            }
            // Popped in name order.
            kids.sort_by(|a, b| b.1.cmp(&a.1));
            stack.extend(kids.into_iter().map(|(obj, n)| (obj, n, Some(mountpoint.clone()))));
        }
        if more {
            self.notes.push(format!("more than {MAX_DATASETS} datasets: the rest are not read"));
        }
        if !errors.is_empty() {
            self.notes.push(format!("datasets not read: {}", listed(&errors)));
        }
        if self.datasets.is_empty() {
            return Err(Error::corrupt("no dataset could be read"));
        }
        Ok(())
    }

    /// Whether dataset `slot`'s top directory has an `etc` directory.
    fn has_etc(&self, cache: &mut Cache, slot: usize) -> bool {
        matches!(self.lookup(cache, slot, None, "etc"), Ok(Some((_, _, Kind::Directory))))
    }

    /// Picks the dataset shown as `/`.
    fn choose_root(&mut self, cache: &mut Cache, bootfs: Option<u64>, pool_name: &str) {
        let usable = |d: &Dataset| d.fs.is_some();
        let by_bootfs = bootfs.and_then(|obj| self.datasets.iter().position(|d| d.ds_obj == obj && usable(d)));
        let at_slash = || {
            self.datasets
                .iter()
                .enumerate()
                .filter(|(_, d)| usable(d) && d.canmount != 0 && d.mountpoint == Mount::Path(String::new()))
                .max_by_key(|(_, d)| (d.canmount == 1, d.birth))
                .map(|(i, _)| i)
        };
        let (root, why) = if let Some(slot) = by_bootfs {
            (Some(slot), "the pool's bootfs")
        } else if let Some(slot) = at_slash() {
            (Some(slot), "its mountpoint is /")
        } else {
            // Only where the system would not mount it by itself (a legacy root that an
            // initramfs mounts): a dataset with a mountpoint is shown there.
            let found = (0..self.datasets.len())
                .filter(|&s| matches!(self.datasets[s].mountpoint, Mount::Legacy | Mount::None))
                .filter(|&s| usable(&self.datasets[s]) && self.has_etc(cache, s))
                .max_by_key(|&s| self.datasets[s].birth);
            (found, "its mountpoint is legacy or none and it holds /etc")
        };
        let Some(slot) = root else {
            self.notes.push(format!(
                "pool `{pool_name}`: no dataset is a root file system; datasets are shown at their mountpoints"
            ));
            return;
        };
        self.notes.push(format!("pool `{pool_name}`: dataset `{}` is read as / ({why})", self.datasets[slot].name));
        // Slot 0, so the files of `/` carry their own object numbers as inode numbers.
        self.datasets.swap(0, slot);
        self.root = Some(0);
    }

    /// Decides where each dataset is shown, and names what is not.
    fn plan_mounts(&mut self, cache: &mut Cache, pool_name: &str) {
        let be_base = format!("{pool_name}/ROOT/");
        let root_name = self.root.map(|r| self.datasets[r].name.clone());
        // The boot environment holding the root, if it is one.
        let active_be = root_name.as_deref().and_then(|n| {
            let rest = n.strip_prefix(&be_base)?;
            Some(format!("{be_base}{}", rest.split('/').next().unwrap_or(rest)))
        });
        let fstab = self.fstab_zfs_lines(cache);
        let (mut bes, mut unmounted, mut zvols, mut encrypted, mut logs, mut taken) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut snapshots = 0;
        let mut paths: HashMap<String, usize> = HashMap::new();
        let mut mounted = Vec::new();
        // In name order: of two datasets with one mountpoint, the first by name is shown.
        let mut order: Vec<usize> = (0..self.datasets.len()).collect();
        order.sort_by(|&a, &b| self.datasets[a].name.cmp(&self.datasets[b].name));
        for slot in order {
            let d = &self.datasets[slot];
            snapshots += d.snapshots;
            if d.has_log {
                logs.push(d.name.clone());
            }
            if Some(slot) == self.root {
                continue;
            }
            // Inside a boot environment that is not the root's.
            if let Some(rest) = d.name.strip_prefix(&be_base) {
                let be = format!("{be_base}{}", rest.split('/').next().unwrap_or(rest));
                if active_be.as_deref() != Some(be.as_str()) {
                    if d.name == be {
                        bes.push(be);
                    }
                    continue;
                }
            }
            if d.os_type == OST_ZVOL {
                zvols.push(d.name.clone());
                continue;
            }
            if d.os_type != OST_ZFS && !d.encrypted {
                continue;
            }
            let point = match &d.mountpoint {
                Mount::Path(p) if d.canmount == 1 => Some(p.trim_start_matches('/').to_string()),
                Mount::Legacy if d.canmount != 0 => fstab.iter().find(|(n, _)| *n == d.name).map(|(_, p)| p.clone()),
                _ => None,
            };
            let Some(point) = point else {
                unmounted.push(d.name.clone());
                continue;
            };
            if point.is_empty() || paths.contains_key(&point) {
                taken.push(format!("{} (/{point})", d.name));
                continue;
            }
            // Mounted only with its key: the system shows what is under the mountpoint.
            if d.encrypted {
                encrypted.push(d.name.clone());
                continue;
            }
            if d.fs.is_none() {
                continue;
            }
            paths.insert(point.clone(), slot);
            mounted.push(format!("/{point} = {}", d.name));
            self.mounts.push((point, slot));
        }
        self.mounts.sort();
        mounted.sort();
        let notes = &mut self.notes;
        let mut note = |list: &[String], what: &str| {
            if !list.is_empty() {
                notes.push(format!("{} {what}: {}", list.len(), listed(list)));
            }
        };
        note(&mounted, "datasets shown at their mountpoints");
        note(&bes, "other boot environments not walked");
        note(
            &unmounted,
            "datasets not mounted (canmount off or noauto, mountpoint none, or legacy with no fstab line)",
        );
        note(&taken, "datasets not walked: their mountpoint is already shown");
        note(&zvols, "volumes (zvols) not read");
        note(&encrypted, "encrypted datasets not read (native encryption)");
        note(&logs, "datasets with intent log records that are not replayed");
        if snapshots > 0 {
            self.notes.push(format!("{snapshots} snapshots not walked"));
        }
    }

    /// The `zfs` lines of the root's `/etc/fstab`: dataset name and mount point.
    fn fstab_zfs_lines(&mut self, cache: &mut Cache) -> Vec<(String, String)> {
        let Some(root) = self.root else { return Vec::new() };
        let text = match self.read_path(cache, root, "etc/fstab") {
            Ok(Some(t)) => t,
            Ok(None) => return Vec::new(),
            Err(e) => {
                self.notes.push(format!("/etc/fstab not read: {e}"));
                return Vec::new();
            }
        };
        let text = String::from_utf8_lossy(&text);
        let mut out = Vec::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [spec, point, fstype, ..] = fields[..] else { continue };
            if spec.starts_with('#') || fstype != "zfs" {
                continue;
            }
            let parts: Vec<&str> = point.split('/').filter(|c| !c.is_empty()).collect();
            if parts.is_empty() || parts.iter().any(|c| *c == "." || *c == "..") {
                continue;
            }
            out.push((spec.to_string(), parts.join("/")));
        }
        out
    }

    /// Entry `name` of directory `dir` (the dataset's top when `None`): object, mode, kind.
    fn lookup(&self, cache: &mut Cache, slot: usize, dir: Option<u64>, name: &str) -> Result<Option<(u64, u64, Kind)>> {
        let fs = self.fs(slot)?;
        let dn = dnode(&self.pool, cache, &fs.meta, dir.unwrap_or(fs.root))?;
        let Some(v) = zap::lookup(&self.pool, cache, &dn, name.as_bytes())? else { return Ok(None) };
        let obj = v.first().unwrap_or(0) & ((1 << INO_BITS) - 1);
        let z = self.znode(cache, slot, obj)?.1;
        Ok(Some((obj, z.mode, kind(z.mode))))
    }

    /// The content of the regular file at `path` in dataset `slot`, if there is one.
    fn read_path(&self, cache: &mut Cache, slot: usize, path: &str) -> Result<Option<Vec<u8>>> {
        let mut dir = None;
        let mut last = None;
        for name in path.split('/') {
            if let Some((_, _, k)) = last {
                if k != Kind::Directory {
                    return Ok(None);
                }
            }
            let Some(found) = self.lookup(cache, slot, dir, name)? else { return Ok(None) };
            dir = Some(found.0);
            last = Some(found);
        }
        let Some((obj, _, Kind::File)) = last else { return Ok(None) };
        let (dn, z) = self.znode(cache, slot, obj)?;
        if z.size > MAX_FSTAB {
            return Err(Error::corrupt("larger than 1 MiB"));
        }
        let mut buf = vec![0u8; z.size as usize];
        dn.read(&self.pool, cache, 0, &mut buf)?;
        Ok(Some(buf))
    }

    fn fs(&self, slot: usize) -> Result<&Fs> {
        let d = self.datasets.get(slot).ok_or_else(|| Error::corrupt(format!("no dataset slot {slot}")))?;
        d.fs.as_ref().ok_or_else(|| Error::unsupported(format!("dataset `{}` is not read", d.name)))
    }

    fn znode(&self, cache: &mut Cache, slot: usize, obj: u64) -> Result<(Dnode, Znode)> {
        let fs = self.fs(slot)?;
        let dn = dnode(&self.pool, cache, &fs.meta, obj)?;
        let z = zpl::znode(&self.pool, cache, fs.sa.as_ref(), &dn)?;
        Ok((dn, z))
    }

    fn symlink(&self, cache: &mut Cache, dn: &Dnode, z: &Znode) -> Result<Vec<u8>> {
        if let Some(t) = &z.symlink {
            return Ok(t.clone());
        }
        if z.size > MAX_SYMLINK {
            return Err(Error::corrupt(format!("symlink of {} bytes", z.size)));
        }
        let mut buf = vec![0u8; z.size as usize];
        dn.read(&self.pool, cache, 0, &mut buf)?;
        Ok(buf)
    }

    /// The top directory of dataset `slot` as a node id: its root object, or an empty
    /// directory when it is not read.
    fn top(&self, slot: usize) -> Option<u64> {
        match &self.datasets[slot].fs {
            Some(fs) => encode(slot, fs.root),
            None => encode(slot, 0).map(|v| v | STUB),
        }
    }

    fn node(&self, cache: &mut Cache, id: u64) -> Result<Node> {
        let (slot, obj, stub) = decode(id);
        if stub || slot == SYNTH {
            return Ok(Node {
                path: String::new(),
                inode: id & !STUB,
                kind: Kind::Directory,
                mode: 0o40755,
                uid: 0,
                gid: 0,
                size: 0,
                allocated: 0,
                links: 2,
                accessed: None,
                modified: None,
                changed: None,
                created: None,
                link_target: None,
            });
        }
        let (dn, z) = self.znode(cache, slot, obj)?;
        let kind = kind(z.mode);
        let link_target = match kind {
            Kind::Symlink => Some(String::from_utf8_lossy(&self.symlink(cache, &dn, &z)?).into_owned()),
            _ => None,
        };
        Ok(Node {
            path: String::new(),
            inode: id,
            kind,
            mode: z.mode as u32,
            uid: z.uid as u32,
            gid: z.gid as u32,
            size: z.size,
            allocated: dn.used,
            links: z.links.min(u64::from(u32::MAX)) as u32,
            accessed: z.atime,
            modified: z.mtime,
            changed: z.ctime,
            created: z.crtime,
            link_target,
        })
    }
}

/// Opens a file system object set: its master node names the top directory and the system
/// attribute tables.
fn open_fs<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, meta: Dnode) -> Result<Fs> {
    let master = dnode(pool, cache, &meta, 1)?;
    let (mut root, mut sa_obj) = (None, None);
    zap::list(pool, cache, &master, &mut |name, v| {
        match name {
            b"ROOT" => root = v.first(),
            b"SA_ATTRS" => sa_obj = v.first(),
            _ => {}
        }
        true
    })?;
    let root = root.ok_or_else(|| Error::corrupt("master node without ROOT"))?;
    let sa = match sa_obj {
        Some(obj) => Some(Sa::load(pool, cache, &|c: &mut Cache, o| dnode(pool, c, &meta, o), obj)?),
        None => None,
    };
    Ok(Fs { meta, root, sa })
}

/// A vdev from its description in a label.
fn build_vdev(nv: &NvList, leaves: &HashMap<u64, usize>, ashift: u64, depth: usize) -> Vdev {
    let guid = nv.u64("guid").unwrap_or(0);
    let kind = nv.str("type").unwrap_or("");
    let children = |depth: usize| -> Vec<Vdev> {
        if depth > 4 {
            return Vec::new();
        }
        nv.lists("children").iter().map(|c| build_vdev(c, leaves, ashift, depth + 1)).collect()
    };
    match kind {
        "disk" | "file" => Vdev::Leaf { guid, dev: leaves.get(&guid).copied() },
        "mirror" | "replacing" | "spare" => Vdev::Mirror(children(depth)),
        "raidz" => {
            let nparity = nv.u64("nparity").unwrap_or(1);
            Vdev::RaidZ { nparity, ashift, children: children(depth) }
        }
        "draid" => Vdev::Unreadable("dRAID vdevs are not read".into()),
        "indirect" => Vdev::Unreadable("blocks of a removed (indirect) vdev are not read".into()),
        other => Vdev::Unreadable(format!("vdev of type `{other}`")),
    }
}

/// Per-walk state.
struct Walker<'w, R> {
    fs: &'w Zfs<R>,
    cache: Cache,
    /// Mount points by path, and for each directory that leads to one, the names under it.
    mounts: HashMap<&'w str, usize>,
    holders: HashMap<String, Vec<String>>,
    /// Paths of the directories made up for mountpoints, by index.
    synthetic: Vec<String>,
}

impl<R: ReadAt> crate::Tree for Walker<'_, R> {
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()> {
        let (slot, obj, stub) = decode(dir);
        let fs = self.fs;
        let names = self.holders.get(path).cloned().unwrap_or_default();
        let mut placed: HashSet<&str> = HashSet::new();
        let (mut large, mut bad, mut damaged) = (0usize, 0usize, 0usize);
        let mut listed = Ok(());
        if !stub && slot != SYNTH {
            let (cache, mounts) = (&mut self.cache, &self.mounts);
            let pool = &fs.pool;
            listed = (|| {
                let meta = &fs.fs(slot)?.meta;
                let dn = dnode(pool, cache, meta, obj)?;
                if dn.kind == OT_PLAIN_FILE {
                    return Err(Error::corrupt("not a directory"));
                }
                damaged = zap::list(pool, cache, &dn, &mut |name, v| {
                    let Some(value) = v.first() else {
                        bad += 1;
                        return true;
                    };
                    let mut child = encode(slot, value & ((1 << INO_BITS) - 1));
                    if !names.is_empty() {
                        let text = String::from_utf8_lossy(name);
                        if let Some(n) = names.iter().find(|n| **n == text) {
                            placed.insert(n.as_str());
                            if let Some(&m) = mounts.get(join(path, n).as_str()) {
                                child = fs.top(m);
                            }
                        }
                    }
                    match child {
                        Some(child) => out.push(child, name),
                        None => {
                            large += 1;
                            true
                        }
                    }
                })?;
                Ok(())
            })();
        }
        // Mountpoints this directory has no entry for.
        for n in &names {
            if placed.contains(n.as_str()) {
                continue;
            }
            let full = join(path, n);
            let child = match self.mounts.get(full.as_str()) {
                Some(&m) => fs.top(m),
                None => {
                    let index = self.synthetic.len() as u64;
                    self.synthetic.push(full);
                    encode(SYNTH, index)
                }
            };
            if let Some(child) = child {
                out.push(child, n.as_bytes());
            }
        }
        for (count, what) in
            [(large, "entries with object numbers above 2^48"), (bad + damaged, "damaged directory entries")]
        {
            if count > 0 {
                warn(format!("{}: {count} {what} skipped", shown(path)));
            }
        }
        listed
    }

    fn node(&mut self, id: u64, _path: &str, _warn: &mut dyn FnMut(String)) -> Result<Node> {
        self.fs.node(&mut self.cache, id)
    }

    fn exhausted(&self) -> bool {
        self.cache.exhausted()
    }
}

impl<R: ReadAt> Volume for Zfs<R> {
    fn kind(&self) -> &'static str {
        "zfs"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()> {
        for note in &self.notes {
            warn(format!("zfs: {note}"));
        }
        let mut holders: HashMap<String, Vec<String>> = HashMap::new();
        for (point, _) in &self.mounts {
            let parts: Vec<&str> = point.split('/').collect();
            for i in 0..parts.len() {
                let names = holders.entry(parts[..i].join("/")).or_default();
                if !names.iter().any(|n| n == parts[i]) {
                    names.push(parts[i].to_string());
                }
            }
        }
        let mut walker = Walker {
            fs: self,
            cache: Cache::new(),
            mounts: self.mounts.iter().map(|(p, s)| (p.as_str(), *s)).collect(),
            holders,
            synthetic: Vec::new(),
        };
        let root = match self.root {
            Some(slot) => self.top(slot),
            None => encode(SYNTH, u64::from(u32::MAX)),
        };
        let root = root.ok_or_else(|| Error::corrupt("root directory object out of range"))?;
        walk_tree("zfs", &mut walker, root, visit, warn)
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (slot, obj, stub) = decode(inode);
        if stub || slot == SYNTH {
            return Err(Error::unsupported("a directory has no content to read"));
        }
        let mut cache = Cache::new();
        let (dn, z) = self.znode(&mut cache, slot, obj)?;
        match kind(z.mode) {
            Kind::File => {
                if offset >= z.size {
                    return Ok(0);
                }
                let n = buf.len().min(usize::try_from(z.size - offset).unwrap_or(usize::MAX));
                dn.read(&self.pool, &mut cache, offset, &mut buf[..n])?;
                Ok(n)
            }
            Kind::Symlink => {
                let target = self.symlink(&mut cache, &dn, &z)?;
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
        assert_eq!(encode(0, 34), Some(34));
        let id = encode(3, 300).unwrap();
        assert_eq!(decode(id), (3, 300, false));
        assert_eq!(decode(id | STUB), (3, 300, true));
        assert_eq!(encode(1, 1 << 48), None);
        assert_eq!(decode(encode(SYNTH, 5).unwrap()), (SYNTH, 5, false));
    }
}

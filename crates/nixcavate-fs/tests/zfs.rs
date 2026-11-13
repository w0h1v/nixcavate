//! ZFS reader against real pools built by `test_files/fs/zfs/build.sh` with OpenZFS, compared
//! with the ground truth the real tools produced from a read-only import (stat, sha256sum,
//! find).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use nixcavate_fs::btrfs::{Compression, Decompress};
use nixcavate_fs::zfs::{member, probe, Zfs};
use nixcavate_fs::{le32, le64, read_all, Bytes, Error, Kind, Node, ReadAt, Slice, Volume};
use sha2::{Digest, Sha256};

/// zlib and zstd for the tests, as nixcavate-source provides them.
struct Codecs;

impl Decompress for Codecs {
    fn decompress(&self, kind: Compression, input: &[u8], out: &mut Vec<u8>, limit: usize) -> nixcavate_fs::Result<()> {
        let reader: Box<dyn Read> = match kind {
            Compression::Zlib => Box::new(flate2::read::ZlibDecoder::new(input)),
            Compression::Zstd => Box::new(zstd::stream::read::Decoder::with_buffer(input)?.single_frame()),
        };
        reader.take(limit as u64).read_to_end(out)?;
        Ok(())
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/zfs").join(name)
}

fn image(name: &str) -> Vec<u8> {
    zstd::decode_all(std::fs::File::open(fixture(&format!("{name}.img.zst"))).unwrap()).unwrap()
}

fn text(name: &str) -> String {
    let path = fixture(name);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => zstd::decode_all(std::fs::File::open(fixture(&format!("{name}.zst"))).unwrap()).unwrap(),
    };
    String::from_utf8(bytes).unwrap()
}

/// The partitions of a GPT image (512-byte sectors), or the whole image when it has none.
fn devices(data: &[u8]) -> Vec<Slice<Bytes<'_>>> {
    if data.get(512..520) != Some(b"EFI PART") {
        return vec![Slice { inner: Bytes(data), start: 0, len: data.len() as u64 }];
    }
    let (first, count, size) = (le64(data, 512 + 72), le32(data, 512 + 80) as usize, le32(data, 512 + 84) as usize);
    (0..count)
        .map(|i| first as usize * 512 + i * size)
        .filter(|&at| data[at..at + 16].iter().any(|&b| b != 0))
        .map(|at| {
            let (start, end) = (le64(data, at + 32) * 512, (le64(data, at + 40) + 1) * 512);
            Slice { inner: Bytes(data), start, len: end - start }
        })
        .collect()
}

fn copy<'a>(s: &Slice<Bytes<'a>>) -> Slice<Bytes<'a>> {
    Slice { inner: Bytes(s.inner.0), start: s.start, len: s.len }
}

/// `seconds.nanoseconds` as printed by `stat %.9Y`; zero means absent.
fn time(s: &str) -> Option<i64> {
    let (sec, frac) = s.split_once('.').unwrap_or((s, "0"));
    let frac: i64 = format!("{frac:0<9}")[..9].parse().unwrap();
    let sec: i64 = sec.parse().unwrap();
    let ns = if s.starts_with('-') { sec * 1_000_000_000 - frac } else { sec * 1_000_000_000 + frac };
    (ns != 0).then_some(ns)
}

fn open<R: ReadAt>(devices: Vec<R>) -> Zfs<R> {
    Zfs::open(devices, Some(Box::new(Codecs))).unwrap()
}

fn walk(fs: &dyn Volume) -> (BTreeMap<String, Node>, Vec<String>) {
    let mut nodes = BTreeMap::new();
    let mut warnings = Vec::new();
    fs.walk(
        &mut |n| {
            assert!(nodes.insert(n.path.clone(), n).is_none(), "path listed twice");
        },
        &mut |w| warnings.push(w),
    )
    .unwrap();
    (nodes, warnings)
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares the walk with the stat listing, every file's content with sha256sum and every
/// symlink with find; returns the walk and its warnings.
fn compare(name: &str, fs: &dyn Volume) -> (BTreeMap<String, Node>, Vec<String>) {
    assert_eq!(fs.kind(), "zfs");
    let (nodes, warnings) = walk(fs);
    let stat = text(&format!("{name}.stat.tsv"));
    let mut expected = 0;
    for line in stat.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 11, "{line}");
        let node = nodes.get(f[0]).unwrap_or_else(|| panic!("{name}: {} not listed; warnings {warnings:?}", f[0]));
        let mode = u32::from_str_radix(f[2], 16).unwrap();
        assert_eq!(node.inode & ((1 << 48) - 1), f[1].parse::<u64>().unwrap(), "{} inode", f[0]);
        assert_eq!(node.mode, mode, "{}", f[0]);
        assert_eq!(node.uid, f[3].parse::<u32>().unwrap(), "{}", f[0]);
        assert_eq!(node.gid, f[4].parse::<u32>().unwrap(), "{}", f[0]);
        assert_eq!(node.size, f[5].parse::<u64>().unwrap(), "{} size", f[0]);
        assert_eq!(node.links, f[6].parse::<u32>().unwrap(), "{} links", f[0]);
        assert_eq!(node.accessed, time(f[7]), "{} atime", f[0]);
        assert_eq!(node.modified, time(f[8]), "{} mtime", f[0]);
        assert_eq!(node.changed, time(f[9]), "{} ctime", f[0]);
        assert_eq!(node.created, time(f[10]), "{} crtime", f[0]);
        let kind = match mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Directory,
            0o120000 => Kind::Symlink,
            _ => Kind::Other,
        };
        assert_eq!(node.kind, kind, "{}", f[0]);
        expected += 1;
    }
    let listed: std::collections::HashSet<&str> = stat.lines().filter_map(|l| l.split('\t').next()).collect();
    let extra: Vec<&String> = nodes.keys().filter(|p| !listed.contains(p.as_str())).collect();
    assert_eq!(nodes.len(), expected, "{name}: extra paths listed: {extra:?}");

    for line in text(&format!("{name}.sha256")).lines() {
        let (hash, path) = line.split_once("  ").unwrap();
        let node = &nodes[path];
        let content = read_all(fs, node.inode, node.size, 1 << 30).unwrap_or_else(|e| panic!("{name}: {path}: {e}"));
        assert_eq!(content.len() as u64, node.size, "{path}");
        assert_eq!(hex(&content), hash, "{name}: {path} content");
    }
    for line in text(&format!("{name}.links.tsv")).lines() {
        let (path, target) = line.split_once('\t').unwrap();
        assert_eq!(nodes[path].link_target.as_deref(), Some(target), "{path}");
        let content = read_all(fs, nodes[path].inode, target.len() as u64, 4096).unwrap();
        assert_eq!(content, target.as_bytes());
    }
    (nodes, warnings)
}

fn check(name: &str) -> (BTreeMap<String, Node>, Vec<String>) {
    let data = image(name);
    let devs = devices(&data);
    assert!(devs.iter().all(|d| probe(d)), "{name}: a member without a label");
    let fs = open(devs);
    compare(name, &fs)
}

/// Reads in odd-sized pieces at odd offsets match one whole read.
fn pieces(fs: &dyn Volume, node: &Node) {
    let whole = read_all(fs, node.inode, node.size, 1 << 30).unwrap();
    let mut offset = 0usize;
    let mut piece = vec![0u8; 4093];
    while offset < whole.len() {
        let n = fs.read(node.inode, offset as u64, &mut piece).unwrap();
        assert!(n > 0);
        assert_eq!(&piece[..n], &whole[offset..offset + n], "{} at {offset}", node.path);
        offset += n + 7919;
    }
    assert_eq!(fs.read(node.inode, node.size, &mut piece).unwrap(), 0);
}

#[test]
fn default_pool() {
    let (nodes, warnings) = check("default");
    assert_eq!(nodes.keys().filter(|p| p.starts_with("dpool/many/")).count(), 3001);
    assert!(nodes["dpool/sparse.bin"].allocated < nodes["dpool/sparse.bin"].size / 16);
    assert_eq!(
        warnings,
        [
            "zfs: pool `dpool`: no dataset is a root file system; datasets are shown at their mountpoints",
            "zfs: 1 datasets shown at their mountpoints: /dpool = dpool",
        ]
    );
    let data = image("default");
    let fs = open(devices(&data));
    for path in ["dpool/sparse.bin", "dpool/rewritten.bin", "dpool/a/b/large.bin"] {
        pieces(&fs, &nodes[path]);
    }
}

#[test]
fn compression() {
    let (nodes, warnings) = check("compress");
    assert!(warnings.iter().all(|w| !w.contains("damaged")), "{warnings:?}");
    let data = image("compress");
    let fs = open(devices(&data));
    for alg in ["off", "lzjb", "gzip-1", "gzip-9", "zle", "lz4", "zstd", "zstd-19"] {
        for file in ["big.txt", "holes.txt", "edited.txt"] {
            pieces(&fs, &nodes[&format!("cpool/{alg}/{file}")]);
        }
    }
    // Without a decompressor, gzip and zstd blocks cannot be read; the others still can.
    let bare = Zfs::open(devices(&data), None).unwrap();
    for (alg, ok) in [("gzip-9", false), ("zstd", false), ("lz4", true), ("lzjb", true), ("zle", true)] {
        let node = &nodes[&format!("cpool/{alg}/big.txt")];
        let read = read_all(&bare, node.inode, node.size, 1 << 30);
        assert_eq!(read.is_ok(), ok, "{alg}");
        if let Err(e) = read {
            assert!(matches!(e, Error::Unsupported(_)), "{e}");
        }
    }
}

#[test]
fn record_sizes_dnodes_and_copies() {
    let (nodes, _) = check("records");
    let data = image("records");
    let fs = open(devices(&data));
    for ds in ["r512", "r128k", "r1m", "copies", "bigdnode", "dirxattr"] {
        for file in ["big.txt", "sparse.bin"] {
            pieces(&fs, &nodes[&format!("rpool2/{ds}/{file}")]);
        }
    }
}

#[test]
fn old_pool_version() {
    let (nodes, _) = check("v28");
    assert_eq!(nodes.keys().filter(|p| p.starts_with("oldpool/many/")).count(), 601);
    let data = image("v28");
    let fs = open(devices(&data));
    pieces(&fs, &nodes["oldpool/sparse.bin"]);
}

#[test]
fn root_pool_layout() {
    let (nodes, warnings) = check("layout");
    assert!(nodes.contains_key("usr/home/alice/.profile") && nodes.contains_key("data/file.txt"));
    assert!(nodes.contains_key("zroot/logclone/clone.txt") && nodes.contains_key("var/log/messages"));
    assert!(!nodes.contains_key("opt/hidden.txt") && !nodes.contains_key("secret/file.txt"));
    assert_eq!(
        warnings,
        [
            "zfs: pool `zroot`: dataset `zroot/ROOT/default` is read as / (the pool's bootfs)",
            "zfs: 7 datasets shown at their mountpoints: /data = zroot/data, /usr/home = zroot/usr/home, \
             /usr/src = zroot/usr/src, /var/log = zroot/var/log, /var/mail = zroot/var/mail, /zroot = zroot, \
             /zroot/logclone = zroot/logclone",
            "zfs: 1 other boot environments not walked: zroot/ROOT/old",
            "zfs: 4 datasets not mounted (canmount off or noauto, mountpoint none, or legacy with no fstab line): \
             zroot/ROOT, zroot/noauto, zroot/usr, zroot/var",
            "zfs: 1 volumes (zvols) not read: zroot/vol",
            "zfs: 1 encrypted datasets not read (native encryption): zroot/secret",
            "zfs: 1 snapshots not walked",
        ]
    );
}

#[test]
fn mirror_either_side() {
    let (all, _) = check("mirror");
    let data = image("mirror");
    let devs = devices(&data);
    assert_eq!(devs.len(), 2);
    // Each side alone is the whole pool; the other side is named as missing only if needed.
    for (side, dev) in devs.iter().enumerate() {
        let fs = open(vec![copy(dev)]);
        let (nodes, warnings) = walk(&fs);
        assert_eq!(nodes.len(), all.len(), "side {side}");
        assert!(!warnings.iter().any(|w| w.contains("not in the image")), "{warnings:?}");
        let node = &nodes["mpool/big.txt"];
        assert_eq!(read_all(&fs, node.inode, node.size, 1 << 30).unwrap().len() as u64, node.size);
    }
}

#[test]
fn stripe_needs_both_members() {
    let (all, _) = check("stripe");
    let data = image("stripe");
    let devs = devices(&data);
    // One member alone: metadata has copies on both (ditto blocks), so the pool opens; the
    // other member is named, and the files it holds cannot be read.
    let mut unreadable = 0;
    for (side, dev) in devs.iter().enumerate() {
        let fs = Zfs::open(vec![copy(dev)], Some(Box::new(Codecs))).unwrap();
        let mut warnings = Vec::new();
        let mut files = Vec::new();
        let _ = fs.walk(&mut |n| files.push(n), &mut |w| warnings.push(w));
        let other = 1 - side;
        assert!(warnings[0].contains(&format!("top-level vdev {other} not in the image")), "{warnings:?}");
        assert_eq!(files.len(), all.len());
        unreadable += files
            .iter()
            .filter(|n| n.kind == Kind::File)
            .filter(|n| matches!(read_all(&fs, n.inode, n.size, 1 << 30), Err(Error::Unsupported(_))))
            .count();
    }
    assert!(unreadable > 0);
}

#[test]
fn raidz() {
    for name in ["raidz1", "raidz2"] {
        let (nodes, _) = check(name);
        let data = image(name);
        let fs = open(devices(&data));
        for path in ["big.txt", "random.bin", "sparse.bin"] {
            let pool = if name == "raidz1" { "zpool1" } else { "zpool2" };
            pieces(&fs, &nodes[&format!("{pool}/{path}")]);
        }
    }
}

#[test]
fn intent_log_is_named_not_replayed() {
    let data = image("dirty");
    let log = image("dirty-log");
    let devs = vec![Bytes(&data[..]), Bytes(&log[..])];
    let fs = open(devs);
    let (_, warnings) = compare("dirty", &fs);
    assert!(warnings.iter().any(|w| w.contains("intent log records")), "{warnings:?}");
    // Without the log device, the pool still reads.
    let fs = open(vec![Bytes(&data[..])]);
    walk(&fs);
}

#[test]
fn members_and_probe() {
    let data = image("mirror");
    let devs = devices(&data);
    let (a, b) = (member(&devs[0]).unwrap(), member(&devs[1]).unwrap());
    assert_eq!(a.0, b.0);
    assert_ne!(a.1, b.1);
    assert!(!probe(&Bytes(&[0u8; 1 << 19])));
    assert!(Zfs::open(vec![Bytes(&[0u8; 1 << 20])], None).is_err());
    assert!(Zfs::open(Vec::<Bytes>::new(), None).is_err());
}

#[test]
fn reads_past_the_end_and_of_non_files() {
    let data = image("default");
    let fs = open(devices(&data));
    let (nodes, _) = walk(&fs);
    let mut buf = [0u8; 16];
    assert_eq!(fs.read(nodes["dpool/small.txt"].inode, 1 << 40, &mut buf).unwrap(), 0);
    assert!(matches!(fs.read(nodes["dpool/a"].inode, 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(matches!(fs.read(nodes["dpool/special/fifo"].inode, 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(fs.read(u64::MAX, 0, &mut buf).is_err());
    assert!(fs.read((1 << 48) | 0xffff_ffff, 0, &mut buf).is_err());
    assert!(fs.read(0xffff_ffff, 0, &mut buf).is_err());
}

// ---------------------------------------------------------------------------------------
// Hostile input: damage written over the real fixtures. Checksums are not verified, so every
// damaged field is parsed.

/// An image with `bytes` written over it at `at`, or cut at `at` when `bytes` is empty.
struct Patched<'a> {
    base: &'a [u8],
    at: usize,
    bytes: &'a [u8],
}

impl ReadAt for Patched<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| std::io::Error::other("offset"))?;
        let len = if self.bytes.is_empty() { self.at } else { self.base.len() };
        let end = start.checked_add(buf.len()).filter(|&e| e <= len);
        let end = end.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "past the end"))?;
        buf.copy_from_slice(&self.base[start..end]);
        let (lo, hi) = (start.max(self.at), end.min(self.at + self.bytes.len()));
        if lo < hi {
            buf[lo - start..hi - start].copy_from_slice(&self.bytes[lo - self.at..hi - self.at]);
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        if self.bytes.is_empty() {
            self.at as u64
        } else {
            self.base.len() as u64
        }
    }
}

/// Opens, walks and reads; returns the number of nodes walked.
fn exercise<R: ReadAt>(devices: Vec<R>) -> usize {
    let Ok(volume) = Zfs::open(devices, Some(Box::new(Codecs))) else { return 0 };
    let mut files = Vec::new();
    let mut count = 0;
    let _ = volume.walk(
        &mut |n| {
            count += 1;
            if files.len() < 64 && matches!(n.kind, Kind::File | Kind::Symlink) {
                files.push(n);
            }
        },
        &mut |_| {},
    );
    let mut buf = vec![0u8; 64 << 10];
    for n in &files {
        let _ = volume.read(n.inode, 0, &mut buf);
        let _ = volume.read(n.inode, n.size.saturating_sub(10), &mut buf);
        let _ = read_all(&volume, n.inode, n.size, 4 << 20);
    }
    count
}

/// Offsets of the 512-byte sectors of `data` that hold anything: labels, uberblocks and
/// every block the pool wrote.
fn used_sectors(data: &[u8]) -> Vec<usize> {
    (0..data.len() / 512).map(|i| i * 512).filter(|&at| data[at..at + 512].iter().any(|&b| b != 0)).collect()
}

/// Boundary values and byte flips over an evenly spread sample of the used sectors of the
/// `layout` pool (labels, uberblocks, the meta object set, dnodes, ZAPs, indirect and data
/// blocks; metadata is lz4-compressed, so most damage lands in compressed streams), and
/// truncations. `ZFS_MUTATIONS` sets the number of sectors damaged (default 600); the
/// exhaustive run, every value at every field of every used sector, is `ZFS_MUTATIONS=0`
/// (in release: about 270,000 pools).
#[test]
fn mutations_neither_panic_nor_hang() {
    let data = image("layout");
    let sectors = used_sectors(&data);
    let wanted: usize = std::env::var("ZFS_MUTATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(600);
    let step = if wanted == 0 { 1 } else { sectors.len().div_ceil(wanted).max(1) };
    let values: [&[u8]; 6] = [&[0xff], &[0], &[0x80, 0, 0, 0], &[0xff; 8], &[1, 0, 0, 0, 0, 0, 0, 0], &[0x7f; 2]];
    let started = std::time::Instant::now();
    let mut cases = 0;
    const FIELDS: [usize; 7] = [0, 8, 48, 64, 100, 300, 507];
    for (n, &sector) in sectors.iter().step_by(step).enumerate() {
        // A different field of each sector (its start, a block pointer word, a ZAP chunk) and
        // value; the exhaustive run writes every value at every field.
        let all = wanted == 0;
        let fields: Vec<usize> = if all { FIELDS.to_vec() } else { vec![FIELDS[n % 7]] };
        let picked: Vec<&[u8]> = if all { values.to_vec() } else { vec![values[n % values.len()]] };
        for field in fields {
            for value in &picked {
                let at = sector + field;
                let one = std::time::Instant::now();
                exercise(vec![Patched { base: &data, at, bytes: value }]);
                assert!(one.elapsed().as_secs() < 20, "damage at {at:#x} took {:?}", one.elapsed());
                cases += 1;
            }
        }
    }
    // Truncations, at the labels and through the data.
    for cut in [0, 1000, 16 << 10, 200 << 10, 1 << 20, 4 << 20, data.len() / 2, data.len() - 1] {
        exercise(vec![Patched { base: &data, at: cut, bytes: &[] }]);
        cases += 1;
    }
    eprintln!("{cases} damaged pools in {:?}", started.elapsed());
}

/// Every uberblock's root pointing past the device, at the uberblock itself, or with sizes
/// that lie: the pool is refused or reads less, never more.
#[test]
fn forged_root_pointers() {
    let clean = image("dirty");
    let (all, _) = walk(&open(vec![Bytes(&clean[..])]));
    let ring_slots: Vec<usize> = (0..4)
        .flat_map(|label| {
            let base = if label < 2 { label * (256 << 10) } else { clean.len() - (4 - label) * (256 << 10) };
            (0..128).map(move |s| base + (128 << 10) + s * 1024)
        })
        .filter(|&at| le64(&clean, at) == 0x00ba_b10c)
        .collect();
    assert!(!ring_slots.is_empty());
    let forge = |f: &dyn Fn(&mut [u8])| {
        let mut d = clean.clone();
        for &at in &ring_slots {
            f(&mut d[at + 40..at + 168]);
        }
        let n = exercise(vec![Bytes(&d[..])]);
        assert!(n <= all.len(), "{n}");
    };
    // The first address past the end of the device.
    forge(&|bp| bp[8..16].copy_from_slice(&(u64::MAX >> 2).to_le_bytes()));
    // A logical size of 32 MiB and a physical one larger than the logical one.
    forge(&|bp| bp[48..50].copy_from_slice(&0xffffu16.to_le_bytes()));
    forge(&|bp| bp[50..52].copy_from_slice(&0xffffu16.to_le_bytes()));
    // Gang bits on every address, and every address pointing at the first label.
    forge(&|bp| bp[15] |= 0x80);
    forge(&|bp| {
        for d in 0..3 {
            bp[d * 16 + 8..d * 16 + 16].copy_from_slice(&[0; 8]);
        }
    });
    // A level, type and compression the reader does not expect.
    forge(&|bp| bp[55] = 31);
    forge(&|bp| bp[54] = 99);
    forge(&|bp| bp[52] = 99);
}

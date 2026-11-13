//! Btrfs reader against real images built by `test_files/fs/btrfs/build.sh`, compared with
//! the ground truth the real tools produced from a kernel mount (stat, sha256sum, find).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use nixcavate_fs::btrfs::{probe, Btrfs, Compression, Decompress};
use nixcavate_fs::{read_all, Bytes, Error, Kind, Node, ReadAt, Volume};
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/btrfs").join(name)
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

/// `seconds.nanoseconds` as printed by `stat %.9Y`; zero means absent.
fn time(s: &str) -> Option<i64> {
    let (sec, frac) = s.split_once('.').unwrap_or((s, "0"));
    let frac: i64 = format!("{frac:0<9}")[..9].parse().unwrap();
    let sec: i64 = sec.parse().unwrap();
    let ns = if s.starts_with('-') { sec * 1_000_000_000 - frac } else { sec * 1_000_000_000 + frac };
    (ns != 0).then_some(ns)
}

fn open(data: &[u8]) -> Btrfs<Bytes<'_>> {
    Btrfs::open(Bytes(data), Some(Box::new(Codecs))).unwrap()
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
fn check(name: &str) -> (BTreeMap<String, Node>, Vec<String>) {
    let data = image(name);
    assert!(probe(&Bytes(&data)));
    let fs = open(&data);
    assert_eq!(fs.kind(), "btrfs");
    let (nodes, warnings) = walk(&fs);

    let mut expected = 0;
    let stat = text(&format!("{name}.stat.tsv"));
    for line in stat.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 11, "{line}");
        let node = nodes.get(f[0]).unwrap_or_else(|| panic!("{name}: {} not listed", f[0]));
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
        let content = read_all(&fs, node.inode, node.size, 1 << 30).unwrap_or_else(|e| panic!("{name}: {path}: {e}"));
        assert_eq!(content.len() as u64, node.size, "{path}");
        assert_eq!(hex(&content), hash, "{name}: {path} content");
    }
    for line in text(&format!("{name}.links.tsv")).lines() {
        let (path, target) = line.split_once('\t').unwrap();
        assert_eq!(nodes[path].link_target.as_deref(), Some(target), "{path}");
        let content = read_all(&fs, nodes[path].inode, target.len() as u64, 4096).unwrap();
        assert_eq!(content, target.as_bytes());
    }
    (nodes, warnings)
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
fn default_layout() {
    let (nodes, warnings) = check("default");
    // The nested subvolume is walked; the snapshot is an empty directory, named once.
    assert!(nodes.contains_key("nested/inside.txt"));
    assert_eq!(nodes["snaps/snap1"].kind, Kind::Directory);
    assert!(!nodes.keys().any(|p| p.starts_with("snaps/snap1/")));
    assert_eq!(warnings, ["btrfs: 1 read-only snapshots not walked (listed as empty directories): /snaps/snap1"]);
    assert!(nodes["nested/inside.txt"].inode >> 48 != 0 && nodes["small.txt"].inode >> 48 == 0);
    assert_eq!(nodes.keys().filter(|p| p.starts_with("many/")).count(), 3001);
    // Holes, preallocated ranges and reflinks, piece by piece.
    let data = image("default");
    let fs = open(&data);
    for path in ["sparse.bin", "prealloc.bin", "keepsize.bin", "reflinked.bin", "shared.bin", "a/b/large.bin"] {
        pieces(&fs, &nodes[path]);
    }
    assert!(nodes["sparse.bin"].allocated < nodes["sparse.bin"].size / 16);
}

#[test]
fn compressed_extents() {
    let (nodes, warnings) = check("compress");
    assert!(warnings.is_empty(), "{warnings:?}");
    let data = image("compress");
    let fs = open(&data);
    for alg in ["zlib", "lzo", "zstd"] {
        for file in ["big.txt", "holes.txt", "edited.txt", "inline.txt", "exact.txt"] {
            pieces(&fs, &nodes[&format!("{alg}/{file}")]);
        }
    }
    // Without a decompressor, zlib and zstd files cannot be read; LZO still can.
    let bare = Btrfs::open(Bytes(&data), None).unwrap();
    for (alg, ok) in [("zlib", false), ("lzo", true), ("zstd", false)] {
        let node = &nodes[&format!("{alg}/big.txt")];
        let read = read_all(&bare, node.inode, node.size, 1 << 30);
        assert_eq!(read.is_ok(), ok, "{alg}");
        if let Err(e) = read {
            assert!(matches!(e, Error::Unsupported(_)), "{e}");
        }
    }
}

#[test]
fn node_sizes() {
    for name in ["node4k", "node64k"] {
        let (nodes, warnings) = check(name);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(nodes.keys().filter(|p| p.starts_with("many/")).count(), 4001);
    }
}

#[test]
fn mixed_block_groups_without_no_holes() {
    let (nodes, warnings) = check("mixed");
    assert!(warnings.is_empty(), "{warnings:?}");
    let data = image("mixed");
    let fs = open(&data);
    for path in ["sparse.bin", "prealloc.bin", "keepsize.bin"] {
        pieces(&fs, &nodes[path]);
    }
}

#[test]
fn fedora_layout() {
    let (nodes, warnings) = check("fedora");
    assert!(nodes.contains_key("home/alice/notes.txt") && nodes.contains_key("var/lib/machines/inside"));
    assert!(!nodes.contains_key("top-level-file"));
    assert_eq!(
        warnings,
        [
            "btrfs: the default subvolume is the top level, which has no /etc: subvolume `root` (id 256) is read as /",
            "btrfs: subvolumes shown where /etc/fstab mounts them: /home = `home` (id 257)",
        ]
    );
}

#[test]
fn suse_layout() {
    let (nodes, warnings) = check("suse");
    assert!(nodes.contains_key("var/log/messages") && nodes.contains_key("home/bob/.profile"));
    assert!(nodes.contains_key(".snapshots/1/info.xml"));
    assert_eq!(nodes[".snapshots/1/snapshot"].kind, Kind::Directory);
    assert_eq!(
        warnings,
        [
            "btrfs: the default subvolume `@` (id 256) is read as /",
            "btrfs: subvolumes shown where /etc/fstab mounts them: /home = `@home` (id 257), /var/log = `log` (id 259), /.snapshots = `.snapshots` (id 260)",
            "btrfs: 1 read-only snapshots not walked (listed as empty directories): /.snapshots/1/snapshot",
            "btrfs: 1 subvolumes neither under / nor mounted by /etc/fstab, not walked: `@unmounted` (id 258)",
        ]
    );
}

#[test]
fn arch_layout() {
    let (nodes, warnings) = check("arch");
    assert!(nodes.contains_key("var/log/pacman.log") && nodes.contains_key("home/carol/file"));
    assert!(!nodes.contains_key("mnt/other"));
    assert_eq!(
        warnings,
        [
            "btrfs: the default subvolume is the top level, which has no /etc: subvolume `@` (id 256) is read as /",
            "btrfs: subvolumes shown where /etc/fstab mounts them: /home = `@home` (id 257), /var/log = `@log` (id 258)",
        ]
    );
}

#[test]
fn reads_past_the_end_and_of_non_files() {
    let data = image("default");
    let fs = open(&data);
    let (nodes, _) = walk(&fs);
    let mut buf = [0u8; 16];
    assert_eq!(fs.read(nodes["small.txt"].inode, 1 << 40, &mut buf).unwrap(), 0);
    assert!(matches!(fs.read(nodes["a"].inode, 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(matches!(fs.read(nodes["special/fifo"].inode, 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(fs.read(u64::MAX, 0, &mut buf).is_err());
    assert!(fs.read((1 << 48) | 0xffff_ffff, 0, &mut buf).is_err());
}

#[test]
fn not_btrfs() {
    assert!(!probe(&Bytes(&[0u8; 1 << 17])));
    assert!(Btrfs::open(Bytes(&[0u8; 1 << 17]), None).is_err());
    assert!(Btrfs::open(Bytes(&[]), None).is_err());
    let data = image("mixed");
    let short = Bytes(&data[..0x10000 + 2048]);
    assert!(probe(&short) && Btrfs::open(&short, None).is_err());
    let _ = short.size();
}

// ---------------------------------------------------------------------------------------
// Hostile input: crafted damage to the real fixtures, then boundary values written over the
// metadata. Checksums are not verified, so every damaged field is parsed.

const SB: usize = 0x10000;

fn get64(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}

fn get32(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
}

fn put64(d: &mut [u8], at: usize, v: u64) {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Image offsets of every tree block: node-size aligned blocks carrying the filesystem id.
fn tree_blocks(d: &[u8]) -> Vec<usize> {
    let nodesize = get32(d, SB + 0x94);
    let fsid = &d[SB + 0x20..SB + 0x30];
    (0..d.len() / nodesize)
        .map(|i| i * nodesize)
        .filter(|&at| at != 0 && &d[at + 0x20..at + 0x30] == fsid && d[at + 0x64] <= 7)
        .collect()
}

/// Leaf items of the block at `at`: (objectid, type, offset, image offset of the data, size).
fn leaf_items(d: &[u8], at: usize) -> Vec<(u64, u8, u64, usize, usize)> {
    if d[at + 0x64] != 0 {
        return Vec::new();
    }
    (0..get32(d, at + 0x60))
        .map(|i| {
            let item = at + 101 + 25 * i;
            (get64(d, item), d[item + 8], get64(d, item + 9), at + 101 + get32(d, item + 17), get32(d, item + 21))
        })
        .collect()
}

/// Walks and reads; returns the number of nodes walked.
fn exercise(volume: &dyn Volume) -> usize {
    let mut nodes = Vec::new();
    let mut count = 0;
    let _ = volume.walk(
        &mut |n| {
            count += 1;
            if nodes.len() < 200 && matches!(n.kind, Kind::File | Kind::Symlink) {
                nodes.push(n);
            }
        },
        &mut |_| {},
    );
    let mut buf = vec![0u8; 64 << 10];
    for n in &nodes {
        let _ = volume.read(n.inode, 0, &mut buf);
        let _ = volume.read(n.inode, n.size.saturating_sub(10), &mut buf);
        let _ = read_all(volume, n.inode, n.size, 4 << 20);
    }
    count
}

fn open_and_exercise(image: &dyn ReadAt) -> usize {
    Btrfs::open(image, Some(Box::new(Codecs))).map(|v| exercise(&v)).unwrap_or(0)
}

#[test]
fn a_block_pointing_at_itself_or_twice_at_one_child_ends_the_scan() {
    let clean = image("node4k");
    let fs = open(&clean);
    let (all, _) = walk(&fs);
    // The root of the top-level file tree: its highest, newest block (old copies stay on disk).
    let inner = tree_blocks(&clean).into_iter().filter(|&at| get64(&clean, at + 0x58) == 5);
    let inner = inner.max_by_key(|&at| (clean[at + 0x64], get64(&clean, at + 0x50))).unwrap();
    assert!(clean[inner + 0x64] > 0);
    let bytenr = get64(&clean, inner + 0x30);
    for patch in [0, 1] {
        let mut d = clean.clone();
        // Every copy of the block (DUP metadata keeps two).
        for at in tree_blocks(&clean).into_iter().filter(|&at| get64(&clean, at + 0x30) == bytenr) {
            let child0 = get64(&d, at + 101 + 17);
            let target = if patch == 0 { bytenr } else { child0 };
            put64(&mut d, at + 101 + 33 + 17, target);
        }
        let fs = Btrfs::open(Bytes(&d), None).unwrap();
        let (nodes, warnings) = walk(&fs);
        assert!(nodes.len() < all.len(), "patch {patch}");
        assert!(
            warnings.iter().any(|w| w.contains("reached twice") || w.contains("levels out of order")),
            "{warnings:?}"
        );
    }
}

#[test]
fn a_subvolume_linked_inside_itself_is_shown_once() {
    let mut d = image("default");
    // The top-level directory entries for the nested subvolume (id 256) now name the top level.
    let mut patched = 0;
    for at in tree_blocks(&d.clone()) {
        for (_, ty, _, data, size) in leaf_items(&d.clone(), at) {
            if (ty == 84 || ty == 96) && size >= 30 && d[data + 8] == 132 && get64(&d, data) == 256 {
                put64(&mut d, data, 5);
                patched += 1;
            }
        }
    }
    assert!(patched >= 2, "{patched}");
    let fs = open(&d);
    let (nodes, _) = walk(&fs);
    assert_eq!(nodes["nested"].kind, Kind::Directory);
    assert!(!nodes.keys().any(|p| p.starts_with("nested/")));
}

#[test]
fn a_chunk_mapped_past_the_device_and_item_data_over_the_headers() {
    let clean = image("mixed");
    // The bootstrap chunk's stripe moved past the end of the image: nothing can be read.
    let mut d = clean.clone();
    let stripe = SB + 0x32b + 17 + 48 + 8;
    put64(&mut d, stripe, u64::MAX - 4096);
    assert!(Btrfs::open(Bytes(&d), None).is_err());
    let end = d.len() as u64 - 4096;
    put64(&mut d, stripe, end);
    assert!(Btrfs::open(Bytes(&d), None).is_err());
    // Every leaf item's data offset pointing into the item headers: such items are skipped.
    let mut d = clean.clone();
    for at in tree_blocks(&clean) {
        if clean[at + 0x64] == 0 && get64(&clean, at + 0x58) == 5 {
            for i in 0..get32(&clean, at + 0x60) {
                put32(&mut d, at + 101 + 25 * i + 17, 0);
            }
        }
    }
    let fs = Btrfs::open(Bytes(&d), None).unwrap();
    let (nodes, _) = walk(&fs);
    assert!(nodes.is_empty());
}

#[test]
fn lying_extent_sizes_stay_bounded() {
    let clean = image("compress");
    let fs = open(&clean);
    let (nodes, _) = walk(&fs);
    let compressed: Vec<(usize, usize)> = tree_blocks(&clean)
        .into_iter()
        .flat_map(|at| leaf_items(&clean, at))
        .filter(|&(_, ty, _, data, size)| ty == 108 && size >= 53 && clean[data + 20] == 1 && clean[data + 16] != 0)
        .map(|(_, _, _, data, size)| (data, size))
        .collect();
    assert!(compressed.len() > 10, "{}", compressed.len());
    // ram_bytes past 128 KiB, smaller than the data, zero; disk_num_bytes huge; an offset past
    // the extent; and a disk address in no chunk.
    for (field, value) in [(8, (128 << 10) + 1), (8, 100), (8, 0), (29, 1 << 40), (37, 1 << 20), (21, 1 << 50)] {
        let mut d = clean.clone();
        for &(data, _) in &compressed {
            put64(&mut d, data + field, value);
        }
        let fs = open(&d);
        for alg in ["zlib", "lzo", "zstd"] {
            let node = &nodes[&format!("{alg}/big.txt")];
            match read_all(&fs, node.inode, node.size, 1 << 30) {
                Ok(data) => assert_eq!(data.len() as u64, node.size),
                Err(e) => assert!(matches!(e, Error::Corrupt(_) | Error::Unsupported(_) | Error::Io(_)), "{e}"),
            }
        }
    }
}

#[test]
fn walks_reuse_tree_blocks() {
    struct Counting<'a>(Bytes<'a>, std::sync::atomic::AtomicU64);
    impl ReadAt for Counting<'_> {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.0.read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
    }
    let data = image("node4k");
    let image = Counting(Bytes(&data), 0.into());
    let fs = Btrfs::open(&image, None).unwrap();
    let before = image.1.load(std::sync::atomic::Ordering::Relaxed);
    let (nodes, _) = walk(&fs);
    let reads = image.1.load(std::sync::atomic::Ordering::Relaxed) - before;
    assert!(reads < nodes.len() as u64 / 4, "{reads} reads for {} nodes", nodes.len());
}

/// One damaged image: `bytes` written over `base` at `at`.
struct Patched<'a> {
    base: &'a [u8],
    at: usize,
    bytes: &'a [u8],
}

impl ReadAt for Patched<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| std::io::Error::other("offset"))?;
        let end = start.checked_add(buf.len()).filter(|&e| e <= self.base.len());
        let end = end.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "past the end"))?;
        buf.copy_from_slice(&self.base[start..end]);
        let (lo, hi) = (start.max(self.at), end.min(self.at + self.bytes.len()));
        if lo < hi {
            buf[lo - start..hi - start].copy_from_slice(&self.bytes[lo - self.at..hi - self.at]);
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.base.len() as u64
    }
}

/// Boundary values of every width at every aligned position of the superblock, the system
/// chunk array and the header, first items and last item data of every tree block. Each case
/// is opened, walked and read on all cores; none may panic, take long or walk too much.
fn mutate(name: &str, sample: Option<usize>) {
    const VALUES: [u64; 15] = [
        0,
        1,
        2,
        0x7f,
        0x80,
        0xff,
        0x7fff,
        0x8000,
        0xffff,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        u64::MAX,
    ];
    let base = image(name);
    let mut ranges = Vec::new();
    ranges.push(SB..SB + 0x32b + 0x200);
    let nodesize = get32(&base, SB + 0x94);
    for at in tree_blocks(&base) {
        ranges.push(at + 0x30..at + 101 + 25 * 6);
        ranges.push(at + nodesize - 160..at + nodesize);
    }
    let mut cases: Vec<(usize, Vec<u8>)> = Vec::new();
    for range in ranges {
        for at in range {
            for width in [1usize, 2, 4, 8] {
                if at % width == 0 {
                    let max = if width == 8 { u64::MAX } else { (1 << (width * 8)) - 1 };
                    cases.extend(VALUES.iter().filter(|&&v| v <= max).map(|v| (at, v.to_le_bytes()[..width].to_vec())));
                }
            }
        }
    }
    // Truncations.
    let truncations = [0usize, 4096, SB, SB + 0x100, SB + 4096, base.len() / 2, base.len() - 4096];
    let step = sample.map_or(1, |n| cases.len().div_ceil(n.max(1)));
    let picked: Vec<&(usize, Vec<u8>)> = cases.iter().step_by(step).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    let started = std::time::Instant::now();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (label, result, took) = if let Some(&&(at, ref bytes)) = picked.get(i) {
                    let image = Patched { base: &base, at, bytes };
                    let t = std::time::Instant::now();
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_and_exercise(&image)));
                    (format!("{bytes:02x?} at {at:#x}"), r, t.elapsed())
                } else if let Some(&len) = truncations.get(i - picked.len()) {
                    let image = Bytes(&base[..len]);
                    let t = std::time::Instant::now();
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_and_exercise(&image)));
                    (format!("truncated to {len}"), r, t.elapsed())
                } else {
                    break;
                };
                let failure = match result {
                    Err(_) => Some("panicked".to_string()),
                    Ok(_) if took > std::time::Duration::from_secs(10) => Some(format!("took {took:?}")),
                    Ok(n) if n > 100_000 => Some(format!("walked {n} nodes")),
                    Ok(_) => None,
                };
                if let Some(f) = failure {
                    failures.lock().unwrap().push(format!("{name}: {label}: {f}"));
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    println!("{name}: {} of {} cases in {:?}", picked.len(), cases.len(), started.elapsed());
    assert!(failures.is_empty(), "{} failures, first: {:?}", failures.len(), &failures[..failures.len().min(20)]);
}

#[test]
fn boundary_values_sample() {
    mutate("mixed", Some(3000));
    mutate("compress", Some(1000));
}

#[test]
#[ignore = "exhaustive: cargo test --release -p nixcavate-fs --test btrfs -- --ignored"]
fn boundary_values_exhaustive() {
    for name in ["mixed", "compress", "suse"] {
        mutate(name, None);
    }
}

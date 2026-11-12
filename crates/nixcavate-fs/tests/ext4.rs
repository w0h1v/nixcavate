//! ext2/3/4 reader against real images built by `test_files/fs/ext4/build.sh`.
//!
//! Ground truth (`NAME.truth.zst`, `NAME.sha256`) was written by `stat`, `readlink` and
//! `sha256sum` while each image was mounted by the Linux kernel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nixcavate_fs::ext4::{self, Ext4};
use nixcavate_fs::{read_all, Bytes, Kind, Node, ReadAt, Volume};
use sha2::{Digest, Sha256};

fn fixture(file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/ext4").join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn image(name: &str) -> Vec<u8> {
    zstd::decode_all(&fixture(&format!("{name}.img.zst"))[..]).unwrap()
}

fn walk(volume: &dyn Volume) -> (Vec<Node>, Vec<String>) {
    let (mut nodes, mut warnings) = (Vec::new(), Vec::new());
    volume.walk(&mut |n| nodes.push(n), &mut |w| warnings.push(w)).unwrap();
    (nodes, warnings)
}

/// `stat -c %.9X` style seconds to nanoseconds; zero is "no time".
fn nanos(field: &str) -> Option<i64> {
    let (secs, frac) = field.split_once('.').unwrap_or((field, "0"));
    let negative = secs.starts_with('-');
    let secs: i64 = secs.parse().unwrap();
    let frac: i64 = format!("{frac:0<9}")[..9].parse().unwrap();
    let ns = secs * 1_000_000_000 + if negative { -frac } else { frac };
    (ns != 0).then_some(ns)
}

/// Compares the walk with the stat listing and every file's content with sha256sum.
fn check_against_truth(name: &str, expect_crtime: bool) {
    let data = image(name);
    let bytes = Bytes(&data);
    assert!(ext4::probe(&bytes));
    let volume = Ext4::open(&bytes).unwrap();
    assert_eq!(volume.kind(), "ext4");
    let (nodes, warnings) = walk(&volume);
    assert!(warnings.is_empty(), "{name}: {warnings:?}");
    let mut by_path = HashMap::new();
    for node in nodes {
        let path = node.path.clone();
        assert!(by_path.insert(path.clone(), node).is_none(), "{name}: {path} listed twice");
    }

    let truth = zstd::decode_all(&fixture(&format!("{name}.truth.zst"))[..]).unwrap();
    let mut seen_crtime = false;
    let mut count = 0;
    for line in truth.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let line = String::from_utf8_lossy(line);
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 12, "{line}");
        let node = by_path.get(f[0]).unwrap_or_else(|| panic!("{name}: {} missing from the walk", f[0]));
        let mode = u32::from_str_radix(f[1], 16).unwrap();
        let ctx = format!("{name}: {}", f[0]);
        assert_eq!(node.mode, mode, "{ctx}: mode");
        let kind = match mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Directory,
            0o120000 => Kind::Symlink,
            _ => Kind::Other,
        };
        assert_eq!(node.kind, kind, "{ctx}: kind");
        assert_eq!(node.inode.to_string(), f[2], "{ctx}: inode");
        assert_eq!(node.links.to_string(), f[3], "{ctx}: links");
        assert_eq!(node.size.to_string(), f[4], "{ctx}: size");
        assert_eq!(node.uid.to_string(), f[5], "{ctx}: uid");
        assert_eq!(node.gid.to_string(), f[6], "{ctx}: gid");
        assert_eq!(node.accessed, nanos(f[7]), "{ctx}: atime");
        assert_eq!(node.modified, nanos(f[8]), "{ctx}: mtime");
        assert_eq!(node.changed, nanos(f[9]), "{ctx}: ctime");
        assert_eq!(node.created, nanos(f[10]), "{ctx}: crtime");
        seen_crtime |= node.created.is_some();
        match kind {
            Kind::Symlink => assert_eq!(node.link_target.as_deref(), Some(f[11]), "{ctx}: target"),
            _ => assert_eq!(node.link_target, None, "{ctx}: target"),
        }
        count += 1;
    }
    assert_eq!(count, by_path.len(), "{name}: the walk found paths stat did not list");
    assert_eq!(seen_crtime, expect_crtime, "{name}: creation times");

    // Content: every non-empty regular file has a digest; empty ones read as nothing.
    let sums = String::from_utf8_lossy(&fixture(&format!("{name}.sha256"))).into_owned();
    let sums: HashMap<&str, &str> = sums.lines().map(|l| (&l[66..], &l[..64])).collect();
    for node in by_path.values().filter(|n| n.kind == Kind::File) {
        let content = read_all(&volume, node.inode, node.size, 256 << 20).unwrap();
        assert_eq!(content.len() as u64, node.size, "{name}: {}", node.path);
        if node.size == 0 {
            continue;
        }
        let digest: String = Sha256::digest(&content).iter().map(|b| format!("{b:02x}")).collect();
        let expected = sums.get(node.path.as_str()).unwrap_or_else(|| panic!("{name}: no digest for {}", node.path));
        assert_eq!(&digest, expected, "{name}: {} content", node.path);
    }
    assert_eq!(sums.len(), by_path.values().filter(|n| n.kind == Kind::File && n.size > 0).count());

    // Targeted reads: the middle of the sparse file, the end of a fragmented file, past the end.
    let sparse = &by_path["sparse"];
    let mut buf = [0xAAu8; 16];
    assert_eq!(volume.read(sparse.inode, 1024 * 1024 - 5, &mut buf).unwrap(), 16);
    assert_eq!(&buf, b"\0\0\0\0\0middle\0\0\0\0\0");
    assert_eq!(volume.read(sparse.inode, 100 * 1024 * 1024, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"end");
    assert_eq!(volume.read(sparse.inode, sparse.size, &mut buf).unwrap(), 0);
    let frag = &by_path["frag"];
    let mut tail = vec![0u8; 3000];
    let n = volume.read(frag.inode, frag.size - 3000, &mut tail).unwrap();
    assert_eq!(n, 3000);
    assert!(tail.windows(15).any(|w| w == b"frag block 399\n"));
    assert!(volume.read(by_path["fifo"].inode, 0, &mut buf).is_err());
}

#[test]
fn ext4_default() {
    check_against_truth("ext4", true);
}

#[test]
fn ext3_block_maps() {
    check_against_truth("ext3", true);
}

#[test]
fn ext4_inline_data() {
    check_against_truth("ext4-inline", true);
}

#[test]
fn ext2_small_inodes() {
    check_against_truth("ext2", false);
}

#[test]
fn ext4_64bit_meta_bg() {
    check_against_truth("ext4-metabg", true);
}

#[test]
fn time_after_2038() {
    let data = image("ext4");
    let bytes = Bytes(&data);
    let volume = Ext4::open(&bytes).unwrap();
    let (nodes, _) = walk(&volume);
    let future = nodes.iter().find(|n| n.path == "future").unwrap();
    // 2040-01-01T00:00:00.5Z
    assert_eq!(future.modified, Some(2_208_988_800_500_000_000));
    let past = nodes.iter().find(|n| n.path == "past").unwrap();
    // 1960-06-15T12:00:00Z
    assert_eq!(past.modified, Some(-301_233_600_000_000_000));
}

#[test]
fn not_ext4() {
    let zeros = vec![0u8; 64 << 10];
    assert!(!ext4::probe(&Bytes(&zeros)));
    assert!(Ext4::open(&Bytes(&zeros)).is_err());
    assert!(!ext4::probe(&Bytes(&[])));
}

#[test]
fn refuses_journal_device() {
    let mut data = image("ext2");
    let incompat = u32::from_le_bytes(data[1120..1124].try_into().unwrap()) | 0x8;
    data[1120..1124].copy_from_slice(&incompat.to_le_bytes());
    assert!(matches!(Ext4::open(&Bytes(&data)), Err(nixcavate_fs::Error::Unsupported(_))));
}

#[test]
fn encrypted_file_is_unreadable_not_the_volume() {
    let mut data = image("ext4");
    let ino = {
        let bytes = Bytes(&data);
        let (nodes, _) = walk(&Ext4::open(&bytes).unwrap());
        nodes.iter().find(|n| n.path == "small.txt").unwrap().inode as usize
    };
    // 4 KiB blocks, one group: descriptors in block 1, 256-byte inodes. Set EXT4_ENCRYPT_FL.
    let table = u32::from_le_bytes(data[4096 + 8..4096 + 12].try_into().unwrap()) as usize;
    let flags = table * 4096 + (ino - 1) * 256 + 0x20;
    data[flags + 1] |= 0x08;
    let bytes = Bytes(&data);
    let volume = Ext4::open(&bytes).unwrap();
    let (nodes, warnings) = walk(&volume);
    assert!(warnings.is_empty());
    assert!(nodes.iter().any(|n| n.path == "small.txt"));
    let mut buf = [0u8; 16];
    assert!(matches!(volume.read(ino as u64, 0, &mut buf), Err(nixcavate_fs::Error::Unsupported(_))));
}

/// Opens, walks and reads a damaged image; must return within `limit` without panicking.
fn exercise(data: &[u8], limit: Duration, what: &str) {
    let start = Instant::now();
    let bytes = Bytes(data);
    if let Ok(volume) = Ext4::open(&bytes) {
        let mut nodes = Vec::new();
        let _ = volume.walk(&mut |n| nodes.push(n), &mut |_| {});
        let mut buf = vec![0u8; 64 << 10];
        for node in &nodes {
            let _ = volume.read(node.inode, 0, &mut buf);
            let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
        }
        for ino in [0, 1, 2, 11, 12, u64::from(u32::MAX), u64::MAX] {
            let _ = volume.read(ino, 0, &mut buf);
        }
    }
    assert!(start.elapsed() < limit, "{what} took {:?}", start.elapsed());
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

/// Byte ranges holding metadata: superblock, descriptors, the start of group 0's inode table,
/// and every non-zero block (directory, extent and indirect blocks among them).
fn metadata_regions(data: &[u8]) -> Vec<(usize, usize)> {
    let le32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    let block_size = 1024usize << le32(1024 + 0x18);
    let gdt = if block_size == 1024 { 2048 } else { block_size };
    let table = le32(gdt + 8) * block_size;
    let mut regions = vec![(1024, 2048), (gdt, gdt + block_size), (table, table + 64 * 256)];
    for (i, block) in data.chunks(block_size).enumerate() {
        if block.iter().any(|&b| b != 0) {
            regions.push((i * block_size, i * block_size + block.len()));
        }
    }
    regions
}

fn corrupt_many(name: &str, seed: u64) {
    let clean = image(name);
    let regions = metadata_regions(&clean);
    let limit = Duration::from_secs(10);
    let mut rng = Rng(seed);
    // Random byte flips in metadata; the first three regions are hit most often.
    for round in 0..500 {
        let mut data = clean.clone();
        for _ in 0..1 + rng.below(8) {
            let pick = if rng.below(2) == 0 { rng.below(3) } else { rng.below(regions.len()) };
            let (start, end) = regions[pick];
            let at = start + rng.below(end - start);
            data[at] ^= 1 << rng.below(8);
            if rng.below(4) == 0 {
                data[at] = [0, 0xFF, 0x80, 0x7F][rng.below(4)];
            }
        }
        exercise(&data, limit, &format!("{name} flip round {round}"));
    }
    // Zeroed blocks.
    for round in 0..150 {
        let mut data = clean.clone();
        let (start, end) = regions[rng.below(regions.len())];
        data[start..end].fill(0);
        exercise(&data, limit, &format!("{name} zero round {round}"));
    }
    // Truncation at many lengths.
    for round in 0..150 {
        let len = if round < 50 { rng.below(64 << 10) } else { rng.below(clean.len()) };
        exercise(&clean[..len], limit, &format!("{name} truncated to {len}"));
    }
}

#[test]
fn damaged_ext4_inline() {
    corrupt_many("ext4-inline", 0x9E37_79B9_7F4A_7C15);
}

#[test]
fn damaged_ext3() {
    corrupt_many("ext3", 0xD1B5_4A32_D192_ED03);
}

#[test]
fn damaged_ext4_metabg() {
    corrupt_many("ext4-metabg", 0x2545_F491_4F6C_DD1D);
}

/// Walk speed on a large image: `NIXCAVATE_EXT4_BENCH=/path/bench.img cargo test --release
/// -p nixcavate-fs --test ext4 -- --ignored --nocapture` (image from `build.sh bench DIR`).
#[test]
#[ignore]
fn walk_speed() {
    use std::os::unix::fs::FileExt;
    struct File(std::fs::File, u64);
    impl ReadAt for File {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
            self.0.read_exact_at(buf, offset)
        }
        fn size(&self) -> u64 {
            self.1
        }
    }
    let path = std::env::var("NIXCAVATE_EXT4_BENCH").expect("NIXCAVATE_EXT4_BENCH");
    let file = std::fs::File::open(path).unwrap();
    let size = file.metadata().unwrap().len();
    let image = File(file, size);
    let start = Instant::now();
    let volume = Ext4::open(&image).unwrap();
    let mut count = 0u64;
    volume.walk(&mut |_| count += 1, &mut |w| panic!("{w}")).unwrap();
    let elapsed = start.elapsed();
    println!("{count} nodes in {elapsed:?}: {:.0} nodes/s", count as f64 / elapsed.as_secs_f64());
}

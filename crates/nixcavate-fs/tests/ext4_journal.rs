//! ext3/ext4 journal replay against images built by `test_files/fs/ext4/journal.sh`: each was
//! copied while mounted, so its newest changes are only in the journal.
//!
//! Ground truth (`NAME.truth.zst`, `NAME.sha256`) was written by `stat`, `readlink` and
//! `sha256sum` on a copy of each image after the Linux kernel replayed its journal (e2fsck for
//! `journal-badcsum`, whose damaged commit block the kernel refuses).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nixcavate_fs::ext4::Ext4;
use nixcavate_fs::{read_all, Bytes, Kind, Node, Volume};
use sha2::{Digest, Sha256};

const JOURNAL_MAGIC: [u8; 4] = [0xC0, 0x3B, 0x39, 0x98];

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

fn hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Every difference between what the reader shows of `data` and the truth of `name`: missing
/// and extra paths, differing fields and file contents.
fn differences(name: &str, data: &[u8]) -> (Vec<String>, Vec<String>) {
    let bytes = Bytes(data);
    let volume = Ext4::open(&bytes).unwrap();
    let (nodes, warnings) = walk(&volume);
    let mut by_path: HashMap<String, Node> = nodes.into_iter().map(|n| (n.path.clone(), n)).collect();
    let mut diffs = Vec::new();

    let truth = zstd::decode_all(&fixture(&format!("{name}.truth.zst"))[..]).unwrap();
    for line in truth.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let line = String::from_utf8_lossy(line);
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 12, "{line}");
        let Some(node) = by_path.remove(f[0]) else {
            diffs.push(format!("{}: missing", f[0]));
            continue;
        };
        let link = (node.kind == Kind::Symlink).then_some(f[11]);
        let fields = [
            ("mode", node.mode == u32::from_str_radix(f[1], 16).unwrap()),
            ("inode", node.inode.to_string() == f[2]),
            ("links", node.links.to_string() == f[3]),
            ("size", node.size.to_string() == f[4]),
            ("uid", node.uid.to_string() == f[5]),
            ("gid", node.gid.to_string() == f[6]),
            ("atime", node.accessed == nanos(f[7])),
            ("mtime", node.modified == nanos(f[8])),
            ("ctime", node.changed == nanos(f[9])),
            ("crtime", node.created == nanos(f[10])),
            ("target", node.link_target.as_deref() == link),
        ];
        for (what, _) in fields.iter().filter(|(_, same)| !same) {
            diffs.push(format!("{}: {what}", f[0]));
        }
        if node.kind == Kind::File && node.size > 0 {
            let sums = String::from_utf8_lossy(&fixture(&format!("{name}.sha256"))).into_owned();
            let expected = sums.lines().find(|l| &l[66..] == f[0]).map(|l| l[..64].to_string());
            let got = read_all(&volume, node.inode, node.size, 64 << 20).map(|c| hex(&c)).ok();
            if got != expected {
                diffs.push(format!("{}: content", f[0]));
            }
        }
    }
    diffs.extend(by_path.keys().map(|p| format!("{p}: not in the truth")));
    (diffs, warnings)
}

/// The volume with its "needs recovery" flag cleared: read as it is on disk.
fn without_replay(mut data: Vec<u8>) -> Vec<u8> {
    data[1024 + 0x60] &= !0x4;
    data
}

/// The fixture equals its truth after replay, with one note saying the journal was replayed,
/// and differs from it without the replay.
fn check(name: &str) -> Vec<String> {
    let data = image(name);
    let (diffs, warnings) = differences(name, &data);
    assert!(diffs.is_empty(), "{name}: {} differences, first {:?}", diffs.len(), &diffs[..diffs.len().min(10)]);
    assert_eq!(warnings.len(), 1, "{name}: {warnings:?}");
    assert!(warnings[0].contains("journal was replayed"), "{name}: {warnings:?}");
    let (stale, _) = differences(name, &without_replay(data));
    assert!(!stale.is_empty(), "{name}: the volume reads the same without the replay");
    warnings
}

#[test]
fn ext4_checksummed_journal() {
    let warnings = check("journal-csum3");
    assert!(warnings[0].contains("45 transactions"), "{warnings:?}");
}

#[test]
fn ext3_journal() {
    check("journal-ext3");
}

#[test]
fn journal_that_wrapped() {
    check("journal-wrap");
}

/// The blocks of a deleted directory were reused for file data: replaying their old journal
/// copies would overwrite that data.
#[test]
fn revoked_blocks_are_not_replayed() {
    check("journal-revoke");
}

/// The last transaction lost its commit block: it was never committed, and is not replayed.
#[test]
fn uncommitted_transaction_is_dropped() {
    let warnings = check("journal-nocommit");
    assert!(warnings[0].contains("44 transactions"), "{warnings:?}");
    let (nodes, _) = walk(&Ext4::open(Bytes(&image("journal-nocommit"))).unwrap());
    assert!(!nodes.iter().any(|n| n.path == "last-transaction"));
    let (nodes, _) = walk(&Ext4::open(Bytes(&image("journal-csum3"))).unwrap());
    assert!(nodes.iter().any(|n| n.path == "last-transaction"));
}

/// A commit block whose checksum does not match ends the replay before its transaction, with
/// a note that says why.
#[test]
fn damaged_commit_block_ends_the_replay() {
    let data = image("journal-badcsum");
    let (diffs, warnings) = differences("journal-badcsum", &data);
    assert!(diffs.is_empty(), "{} differences, first {:?}", diffs.len(), &diffs[..diffs.len().min(10)]);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("44 transactions") && warnings[0].contains("checksum"), "{warnings:?}");
}

/// The fixtures' journal: the range of blocks from the first to the last that starts with the
/// journal magic (each small image's journal is one extent), and the block size.
fn journal_area(data: &[u8]) -> (usize, usize, usize) {
    let bs = 1024usize << u32::from_le_bytes(data[1024 + 0x18..1024 + 0x1C].try_into().unwrap());
    let blocks: Vec<usize> = (0..data.len() / bs).filter(|&b| data[b * bs..b * bs + 4] == JOURNAL_MAGIC).collect();
    (blocks[0] * bs, (blocks[blocks.len() - 1] + 1) * bs, bs)
}

/// Opens, walks and reads a damaged image; must return within `limit` without panicking.
fn exercise(data: &[u8], limit: Duration, what: &str) {
    let start = Instant::now();
    let bytes = Bytes(data);
    if let Ok(volume) = Ext4::open(&bytes) {
        let mut nodes = Vec::new();
        let mut warnings = 0;
        let _ = volume.walk(&mut |n| nodes.push(n), &mut |_| warnings += 1);
        let mut buf = vec![0u8; 64 << 10];
        for node in &nodes {
            let _ = volume.read(node.inode, 0, &mut buf);
            let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
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

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// Byte flips, zeroed blocks and boundary values all over the journal of every fixture.
#[test]
fn damaged_journals() {
    let limit = Duration::from_secs(10);
    for (name, seed) in [
        ("journal-csum3", 0x9E37_79B9_7F4A_7C15u64),
        ("journal-ext3", 0xD1B5_4A32_D192_ED03),
        ("journal-wrap", 0x2545_F491_4F6C_DD1D),
        ("journal-revoke", 0x5851_F42D_4C95_7F2D),
    ] {
        let clean = image(name);
        let (start, end, bs) = journal_area(&clean);
        let mut rng = Rng(seed);
        // The journal blocks that hold structure: superblock, descriptors, commits, revokes.
        let headers: Vec<usize> =
            (start / bs..end / bs).filter(|&b| clean[b * bs..b * bs + 4] == JOURNAL_MAGIC).collect();
        for round in 0..400 {
            let mut data = clean.clone();
            for _ in 0..1 + rng.below(6) {
                let block = headers[rng.below(headers.len())];
                // Mostly the header and the first tags or records.
                let within = if rng.below(2) == 0 { rng.below(64) } else { rng.below(bs) };
                let at = block * bs + within;
                data[at] ^= 1 << rng.below(8);
                if rng.below(4) == 0 {
                    data[at] = [0, 0xFF, 0x80, 0x7F][rng.below(4)];
                }
            }
            exercise(&data, limit, &format!("{name} flip round {round}"));
        }
        for _ in 0..100 {
            let mut data = clean.clone();
            let block = headers[rng.below(headers.len())];
            data[block * bs..(block + 1) * bs].fill(0);
            exercise(&data, limit, &format!("{name} zeroed journal block {block}"));
        }
        for _ in 0..50 {
            let len = start + rng.below(end - start);
            exercise(&clean[..len], limit, &format!("{name} truncated to {len}"));
        }
        // Boundary values in each field of the journal superblock (big-endian, 4 bytes).
        for field in (0x0C..0x60).step_by(4) {
            for value in [0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x400, 0xFFFF, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
                let mut data = clean.clone();
                put_be32(&mut data, start + field, value);
                exercise(&data, limit, &format!("{name} journal superblock {field:#x} = {value:#x}"));
            }
        }
    }
}

/// Descriptor tags that name blocks outside the volume, or the journal's own superblock, and
/// commit blocks that disagree with the superblock's block size: the volume still opens.
#[test]
fn forged_tags_and_layouts() {
    let clean = image("journal-ext3");
    let (start, end, bs) = journal_area(&clean);
    let descriptors: Vec<usize> = (start / bs..end / bs)
        .filter(|&b| clean[b * bs..b * bs + 4] == JOURNAL_MAGIC && clean[b * bs + 4..b * bs + 8] == [0, 0, 0, 1])
        .collect();
    assert!(!descriptors.is_empty());
    let limit = Duration::from_secs(10);
    for value in [0, 1, u32::MAX, 0x7FFF_FFFF, (clean.len() / bs) as u32, (start / bs) as u32] {
        let mut data = clean.clone();
        for &d in &descriptors {
            // ext3 tags without checksums: 8 bytes each, plus 16 for the first one's UUID.
            put_be32(&mut data, d * bs + 12, value);
            put_be32(&mut data, d * bs + 12 + 8 + 16, value);
        }
        exercise(&data, limit, &format!("tags naming block {value:#x}"));
        let volume = Ext4::open(Bytes(&data)).unwrap();
        let (nodes, warnings) = walk(&volume);
        assert!(!nodes.is_empty() && !warnings.is_empty());
    }
    // A journal superblock whose block size is not the volume's: not replayed, one note.
    let mut data = clean.clone();
    put_be32(&mut data, start + 0x0C, 4096);
    let (_, warnings) = walk(&Ext4::open(Bytes(&data)).unwrap());
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("not replayed"), "{warnings:?}");
    // `start` past the end, `first` past `maxlen`: not replayed.
    for (field, value) in [(0x1C, u32::MAX), (0x14, u32::MAX), (0x10, 1), (0x10, u32::MAX)] {
        let mut data = clean.clone();
        put_be32(&mut data, start + field, value);
        let (_, warnings) = walk(&Ext4::open(Bytes(&data)).unwrap());
        assert!(warnings.iter().any(|w| w.contains("not replayed")), "{field:#x}={value:#x}: {warnings:?}");
    }
}

/// Every block of the journal turned into a descriptor of the expected sequence, so the log
/// never ends: the scan stops after one pass round the journal, and says so. The journal is
/// one extent; its checksum feature is cleared so checksums do not end the log first.
#[test]
fn a_log_without_end_stops() {
    let clean = image("journal-wrap");
    let (start, _, bs) = journal_area(&clean);
    let be = |at: usize| u32::from_be_bytes(clean[at..at + 4].try_into().unwrap());
    let (maxlen, sequence) = (be(start + 0x10) as usize, be(start + 0x18));
    let mut data = clean.clone();
    put_be32(&mut data, start + 0x28, 0);
    for b in 1..maxlen {
        let at = start + b * bs;
        data[at..at + bs].fill(0);
        data[at..at + 4].copy_from_slice(&JOURNAL_MAGIC);
        put_be32(&mut data, at + 4, 1);
        put_be32(&mut data, at + 8, sequence);
    }
    exercise(&data, Duration::from_secs(10), "endless descriptors");
    let (_, warnings) = walk(&Ext4::open(Bytes(&data)).unwrap());
    assert!(warnings.iter().any(|w| w.contains("runs past")), "{warnings:?}");
}

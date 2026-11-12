//! Boundary values (0, 1, 2, 0x7f, 0x80, 0xff, 0x7fff, ... u64::MAX) written as 8-, 16-, 32-
//! and 64-bit integers at every position of the metadata of the real fixtures: superblocks,
//! group descriptors, inodes, directory, bmbt and symlink blocks, and every checksummed APFS
//! object (with its checksum recomputed, so the reader parses the damaged fields). Each damaged
//! image is opened, walked and read; none may panic, take long or report an outsized walk.
//!
//! `cargo test` runs an evenly spread sample of the cases of a few images; the exhaustive run
//! over every case of every fixture is `cargo test --release -p nixcavate-fs --test mutation
//! -- --ignored`.

use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nixcavate_fs::apfs::Apfs;
use nixcavate_fs::ext4::Ext4;
use nixcavate_fs::xfs::Xfs;
use nixcavate_fs::{read_all, Kind, ReadAt, Volume};

/// One damaged image: `bytes` written over `base` at `at`.
type Case = (usize, Vec<u8>);

struct Patched<'a> {
    base: &'a [u8],
    at: usize,
    bytes: &'a [u8],
}

impl ReadAt for Patched<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::Error::other("offset"))?;
        let end = start.checked_add(buf.len()).filter(|&e| e <= self.base.len());
        let end = end.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"))?;
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

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

/// Every boundary value that fits `width` bytes, encoded.
fn values(width: usize, endian: Endian) -> impl Iterator<Item = Vec<u8>> {
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
    let max = if width == 8 { u64::MAX } else { (1 << (width * 8)) - 1 };
    VALUES.into_iter().filter(move |&v| v <= max).map(move |v| match endian {
        Endian::Little => v.to_le_bytes()[..width].to_vec(),
        Endian::Big => v.to_be_bytes()[8 - width..].to_vec(),
    })
}

/// Cases for every aligned 1-, 2-, 4- and 8-byte field in `range`.
fn fields(range: std::ops::Range<usize>, endian: Endian, out: &mut Vec<Case>) {
    for at in range {
        for width in [1, 2, 4, 8] {
            if at % width == 0 {
                out.extend(values(width, endian).map(|v| (at, v)));
            }
        }
    }
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

/// Runs `cases` (every one, or `sample` of them spread evenly) on all cores. With `resign`,
/// each case damages a checksummed APFS object, which is re-signed before use.
fn run(
    name: &str,
    base: &[u8],
    cases: Vec<Case>,
    sample: Option<usize>,
    resign: bool,
    open: &(dyn Fn(&dyn ReadAt) -> usize + Sync),
) {
    let step = sample.map_or(1, |n| cases.len().div_ceil(n.max(1)));
    let picked: Vec<&Case> = cases.iter().step_by(step).collect();
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let started = Instant::now();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while let Some(&&(at, ref bytes)) = picked.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let block = resign.then(|| {
                        let start = at / 4096 * 4096;
                        let mut b = base[start..start + 4096].to_vec();
                        b[at - start..at - start + bytes.len()].copy_from_slice(bytes);
                        let sum = fletcher64(&b[8..]);
                        b[..8].copy_from_slice(&sum.to_le_bytes());
                        (start, b)
                    });
                    let image = match &block {
                        Some((start, b)) => Patched { base, at: *start, bytes: b },
                        None => Patched { base, at, bytes },
                    };
                    let t = Instant::now();
                    let result = catch_unwind(AssertUnwindSafe(|| open(&image)));
                    let took = t.elapsed();
                    let failure = match result {
                        Err(_) => Some("panicked".to_string()),
                        Ok(_) if took > Duration::from_secs(10) => Some(format!("took {took:?}")),
                        Ok(n) if n > 100_000 => Some(format!("walked {n} nodes")),
                        Ok(_) => None,
                    };
                    if let Some(f) = failure {
                        failures.lock().unwrap().push(format!("{name}: {bytes:02x?} at {at:#x}: {f}"));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    println!("{name}: {} of {} cases in {:?}", picked.len(), cases.len(), started.elapsed());
    assert!(failures.is_empty(), "{} failures, first: {:?}", failures.len(), &failures[..failures.len().min(20)]);
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs").join(rel);
    zstd::decode_all(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))[..]).unwrap()
}

fn le16(d: &[u8], at: usize) -> usize {
    u16::from_le_bytes(d[at..at + 2].try_into().unwrap()) as usize
}

fn le32(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
}

fn be32(d: &[u8], at: usize) -> u64 {
    u64::from(u32::from_be_bytes(d[at..at + 4].try_into().unwrap()))
}

fn ext4(name: &str, sample: Option<usize>) {
    let d = fixture(&format!("ext4/{name}.img.zst"));
    let mut cases = Vec::new();
    fields(1024..1024 + 0x180, Endian::Little, &mut cases);
    let bs = 1024 << le32(&d, 1024 + 0x18);
    let gdt = if bs == 1024 { 2048 } else { bs };
    fields(gdt..gdt + 128, Endian::Little, &mut cases);
    let isz = if le32(&d, 1024 + 0x4c) == 0 { 128 } else { le16(&d, 1024 + 0x58) };
    let table = le32(&d, gdt + 8) * bs;
    for ino in 1..=24 {
        let at = table + (ino - 1) * isz;
        fields(at..at + isz.min(0xa0), Endian::Little, &mut cases);
    }
    // The root directory's first block, from its extent or its first direct pointer.
    let root = table + isz;
    let extents = le32(&d, root + 0x20) & 0x8_0000 != 0;
    let block = if extents { le32(&d, root + 0x28 + 20) } else { le32(&d, root + 0x28) };
    fields(block * bs..block * bs + 128, Endian::Little, &mut cases);
    run(name, &d, cases, sample, false, &|image| Ext4::open(image).map(|v| exercise(&v)).unwrap_or(0));
}

fn xfs(name: &str, sample: Option<usize>) {
    let d = fixture(&format!("xfs/{name}.img.zst"));
    let mut cases = Vec::new();
    fields(0..264, Endian::Big, &mut cases);
    let bs = be32(&d, 4) as usize;
    let (blog, ilog, inopb, agblog) = (u64::from(d[120]), u64::from(d[122]), u64::from(d[123]), u64::from(d[124]));
    let root = u64::from_be_bytes(d[56..64].try_into().unwrap());
    let agbn = (root >> inopb) & ((1 << agblog) - 1);
    let agno = root >> (inopb + agblog);
    let pos = (((agno * be32(&d, 84) + agbn) << blog) + ((root & ((1 << inopb) - 1)) << ilog)) as usize;
    for i in 0..48 {
        let at = pos + (i << ilog);
        fields(at..at + 176 + 48, Endian::Big, &mut cases);
    }
    // The first directory, bmbt and remote symlink blocks: headers and tails.
    let magics: [&[u8]; 11] =
        [b"XD2B", b"XDB3", b"XD2D", b"XDD3", b"BMA3", b"BMAP", b"XSLM", b"XD2L", b"XDL3", b"XD2F", b"XDF3"];
    for (i, _) in d.chunks(bs).enumerate().filter(|(_, b)| magics.contains(&&b[..4])).take(12) {
        fields(i * bs..i * bs + 96, Endian::Big, &mut cases);
        fields(i * bs + bs - 16..i * bs + bs, Endian::Big, &mut cases);
    }
    run(name, &d, cases, sample, false, &|image| Xfs::open(image).map(|v| exercise(&v)).unwrap_or(0));
}

fn fletcher64(data: &[u8]) -> u64 {
    let (mut s1, mut s2) = (0u64, 0u64);
    for w in data.chunks_exact(4) {
        s1 = (s1 + u64::from(u32::from_le_bytes(w.try_into().unwrap()))) % 0xffff_ffff;
        s2 = (s2 + s1) % 0xffff_ffff;
    }
    let c1 = 0xffff_ffff - (s1 + s2) % 0xffff_ffff;
    let c2 = 0xffff_ffff - (s1 + c1) % 0xffff_ffff;
    (c2 << 32) | c1
}

/// The APFS partition of a GPT disk image with 512-byte sectors.
fn apfs_partition(d: &[u8]) -> &[u8] {
    let entries = le32(d, 512 + 72) * 512;
    for e in d[entries..entries + 128 * 128].chunks(128) {
        if e[..4] == [0xef, 0x57, 0x34, 0x7c] {
            let first = le32(e, 32) * 512;
            let last = le32(e, 40) * 512;
            return &d[first..last + 512];
        }
    }
    panic!("no APFS partition");
}

/// Cases damage a checksummed object, which is then re-signed: every superblock, object map
/// and checkpoint object, and every B-tree node whose block number is a multiple of `every`.
fn apfs(name: &str, every: usize, sample: Option<usize>) {
    let disk = fixture(&format!("apfs/{name}.dmg.zst"));
    let part = apfs_partition(&disk);
    let mut cases = Vec::new();
    for (i, block) in part.chunks(4096).enumerate() {
        let sum = u64::from_le_bytes(block[..8].try_into().unwrap());
        if block.iter().all(|&b| b == 0) || sum != fletcher64(&block[8..]) {
            continue;
        }
        let kind = le32(block, 24) & 0xffff;
        if (kind == 2 || kind == 3) && i % every != 0 {
            continue;
        }
        fields(i * 4096 + 8..i * 4096 + 400, Endian::Little, &mut cases);
        fields(i * 4096 + 4096 - 160..i * 4096 + 4096, Endian::Little, &mut cases);
    }
    run(name, part, cases, sample, true, &|image| {
        let Ok(container) = Apfs::open(image) else { return 0 };
        let volumes = container.volumes();
        volumes.iter().filter_map(|v| container.volume(v.index).ok()).map(|v| exercise(&v)).sum()
    });
}

#[test]
fn boundary_values_ext4_sample() {
    ext4("ext4", Some(1500));
    ext4("ext3", Some(1000));
}

#[test]
fn boundary_values_xfs_sample() {
    xfs("v5", Some(400));
}

#[test]
fn boundary_values_apfs_sample() {
    apfs("cs", 1, Some(1500));
    apfs("basic", 12, Some(250));
}

#[test]
#[ignore]
fn boundary_values_exhaustive() {
    for name in ["ext4", "ext3", "ext2", "ext4-inline", "ext4-metabg"] {
        ext4(name, None);
    }
    for name in ["v5", "v5-1k", "v4"] {
        xfs(name, None);
    }
    apfs("cs", 1, None);
    apfs("basic", 12, None);
}

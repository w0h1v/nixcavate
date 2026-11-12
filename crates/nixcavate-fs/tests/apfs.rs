//! APFS reader against images made by macOS `hdiutil` (test_files/fs/apfs/build.sh), checked
//! against ground truth that `stat`, `readlink` and `shasum` recorded on the mounted volumes.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::time::{Duration, Instant};

use nixcavate_fs::apfs::{self, Apfs};
use nixcavate_fs::{read_all, Bytes, Error, Kind, Node, ReadAt, Slice, Volume};

const CHUNK: usize = 4096;

/// A disk image held as its non-zero 4 KiB chunks: the multi-volume image is 1.1 GiB.
struct Sparse {
    chunks: HashMap<u64, Vec<u8>>,
    size: u64,
}

impl Sparse {
    fn load(path: &str) -> Sparse {
        let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut z = zstd::Decoder::new(file).unwrap();
        let (mut chunks, mut size) = (HashMap::new(), 0u64);
        loop {
            let mut buf = vec![0u8; CHUNK];
            let mut got = 0;
            while got < CHUNK {
                match z.read(&mut buf[got..]).unwrap() {
                    0 => break,
                    n => got += n,
                }
            }
            if got == 0 {
                break;
            }
            if buf.iter().any(|&b| b != 0) {
                chunks.insert(size / CHUNK as u64, buf);
            }
            size += got as u64;
        }
        Sparse { chunks, size }
    }
}

impl ReadAt for Sparse {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.size) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"));
        }
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done as u64;
            let (chunk, within) = (at / CHUNK as u64, (at % CHUNK as u64) as usize);
            let n = (CHUNK - within).min(buf.len() - done);
            match self.chunks.get(&chunk) {
                Some(c) => buf[done..done + n].copy_from_slice(&c[within..within + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// (start, length) of the APFS partition in a GPT disk with 512-byte sectors.
fn apfs_partition(disk: &dyn ReadAt) -> (u64, u64) {
    const APFS_TYPE: [u8; 16] = [0xef, 0x57, 0x34, 0x7c, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac];
    let mut header = [0u8; 92];
    disk.read_at(512, &mut header).unwrap();
    assert_eq!(&header[..8], b"EFI PART");
    let entries = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap());
    let size = u32::from_le_bytes(header[84..88].try_into().unwrap());
    for i in 0..u64::from(count) {
        let mut e = vec![0u8; size as usize];
        disk.read_at(entries * 512 + i * u64::from(size), &mut e).unwrap();
        if e[..16] == APFS_TYPE {
            let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
            let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
            return (first * 512, (last - first + 1) * 512);
        }
    }
    panic!("no APFS partition");
}

fn fixture_path(name: &str) -> String {
    format!("{}/../../test_files/fs/apfs/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// One line of a ground-truth listing written by build.sh.
struct Truth {
    path: String,
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    links: u32,
    mtime: i64,
    birth: i64,
    target: String,
    sha256: String,
}

fn truth(name: &str) -> Vec<Truth> {
    let raw = std::fs::read(fixture_path(name)).unwrap();
    let text = if name.ends_with(".zst") { zstd::decode_all(&raw[..]).unwrap() } else { raw };
    let ns = |s: &str| {
        let (secs, frac) = s.split_once('.').unwrap();
        secs.parse::<i64>().unwrap() * 1_000_000_000 + frac.parse::<i64>().unwrap()
    };
    String::from_utf8(text)
        .unwrap()
        .lines()
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 11, "{line}");
            Truth {
                path: f[0].to_string(),
                kind: match f[1] {
                    "Regular File" => Kind::File,
                    "Directory" => Kind::Directory,
                    "Symbolic Link" => Kind::Symlink,
                    other => panic!("type {other}"),
                },
                mode: u32::from_str_radix(f[2], 8).unwrap(),
                uid: f[3].parse().unwrap(),
                gid: f[4].parse().unwrap(),
                size: f[5].parse().unwrap(),
                links: f[6].parse().unwrap(),
                mtime: ns(f[7]),
                birth: ns(f[8]),
                target: f[9].to_string(),
                sha256: f[10].to_string(),
            }
        })
        .collect()
}

fn walk(volume: &dyn Volume) -> (Vec<Node>, Vec<String>) {
    let (mut nodes, mut warnings) = (Vec::new(), Vec::new());
    volume.walk(&mut |n| nodes.push(n), &mut |w| warnings.push(w)).unwrap();
    (nodes, warnings)
}

/// Compares a volume with its ground truth: every path, type, mode, owner (when the mount
/// recorded real owners), size (except directories, whose stat size APFS synthesizes), link
/// count, modification and birth time, symlink target and content hash. Files in
/// `unsupported` must fail to read with `Error::Unsupported`. Returns the walked nodes by path.
fn check(volume: &dyn Volume, truth: &[Truth], owners: bool, unsupported: &[&str]) -> BTreeMap<String, Node> {
    assert_eq!(volume.kind(), "apfs");
    let (nodes, warnings) = walk(volume);
    assert!(warnings.is_empty(), "{warnings:?}");
    let nodes: BTreeMap<String, Node> =
        nodes.into_iter().filter(|n| !n.path.starts_with(".fseventsd")).map(|n| (n.path.clone(), n)).collect();
    let want: Vec<&str> = truth.iter().map(|t| t.path.as_str()).collect();
    let got: Vec<&str> = nodes.keys().map(String::as_str).collect();
    assert_eq!(got, want);
    for t in truth {
        let n = &nodes[&t.path];
        let p = &t.path;
        assert_eq!((n.kind, n.mode, n.links), (t.kind, t.mode, t.links), "{p}");
        if owners {
            assert_eq!((n.uid, n.gid), (t.uid, t.gid), "{p}");
        }
        assert_eq!((n.modified, n.created), (Some(t.mtime), Some(t.birth)), "{p}");
        assert!(n.accessed.is_some() && n.changed.is_some(), "{p}");
        if t.kind != Kind::Directory {
            assert_eq!(n.size, t.size, "{p}");
        }
        assert_eq!(n.link_target.as_deref(), (t.kind == Kind::Symlink).then_some(t.target.as_str()), "{p}");
        if t.kind == Kind::File {
            match read_all(volume, n.inode, n.size, 64 << 20) {
                Ok(data) => {
                    assert!(!unsupported.contains(&p.as_str()), "{p} should be unsupported");
                    assert_eq!(sha256_hex(&data), t.sha256, "{p}");
                }
                Err(Error::Unsupported(m)) if unsupported.contains(&p.as_str()) => {
                    assert!(m.starts_with("decmpfs compression type"), "{p}: {m}")
                }
                Err(e) => panic!("{p}: {e}"),
            }
        }
    }
    nodes
}

fn open_disk(name: &str) -> (Sparse, u64, u64) {
    let disk = Sparse::load(&fixture_path(name));
    let (start, len) = apfs_partition(&disk);
    (disk, start, len)
}

#[test]
fn basic_volume_matches_ground_truth() {
    let (disk, start, len) = open_disk("basic.dmg.zst");
    assert!(!apfs::probe(&disk), "the GPT disk itself is not a container");
    let part = Slice { inner: &disk, start, len };
    assert!(apfs::probe(&part));
    let container = Apfs::open(&part).unwrap();
    let volumes = container.volumes();
    assert_eq!(volumes.len(), 1);
    let v = &volumes[0];
    assert_eq!(
        (v.index, v.name.as_str(), v.role_name(), v.encrypted, v.case_sensitive),
        (0, "TestVol", "none", false, false)
    );
    assert!(container.snapshots(0).unwrap().is_empty());

    let volume = container.volume(0).unwrap();
    let nodes = check(&volume, &truth("basic.tsv.zst"), true, &["comp-large.txt"]);

    // Hard links share an inode; a clone has its own.
    let inode = |p: &str| nodes[p].inode;
    assert_eq!(inode("small.txt"), inode("hardlink.txt"));
    assert_eq!(inode("small.txt"), inode("dir1/hardlink2.txt"));
    assert_ne!(inode("big.bin"), inode("clone.bin"));
    assert_eq!(nodes["largedir"].links, 3002);

    // Reads at offsets: inside holes, across extents, past the end.
    let mut buf = [0xaau8; 10];
    assert_eq!(volume.read(inode("sparse.bin"), (2 << 20) - 2, &mut buf).unwrap(), 10);
    assert_eq!(&buf, b"\0\0middle\0\0");
    assert_eq!(volume.read(inode("sparse.bin"), (5 << 20) + 2, &mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"il");
    assert_eq!(volume.read(inode("sparse.bin"), 6 << 20, &mut buf).unwrap(), 0);
    for (file, size) in [("frag-a.bin", 196_608), ("comp-zlib.txt", 9600)] {
        let whole = read_all(&volume, inode(file), size, size).unwrap();
        let mut pieces = Vec::new();
        let mut chunk = [0u8; 999];
        loop {
            let n = volume.read(inode(file), pieces.len() as u64, &mut chunk).unwrap();
            if n == 0 {
                break;
            }
            pieces.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(pieces, whole, "{file}");
    }
    assert!(matches!(volume.read(inode("dir1"), 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(matches!(volume.read(inode("link-short"), 0, &mut buf), Err(Error::Unsupported(_))));
    assert!(volume.read(0x0fff_ffff, 0, &mut buf).is_err());
}

#[test]
fn case_sensitive_volume_matches_ground_truth() {
    let (disk, start, len) = open_disk("cs.dmg.zst");
    let part = Slice { inner: &disk, start, len };
    let container = Apfs::open(&part).unwrap();
    let volumes = container.volumes();
    assert_eq!((volumes.len(), volumes[0].name.as_str(), volumes[0].case_sensitive), (1, "CaseVol", true));
    check(&container.volume(0).unwrap(), &truth("cs.tsv"), true, &[]);
}

#[test]
fn multi_volume_container() {
    let (disk, start, len) = open_disk("multi.dmg.zst");
    let part = Slice { inner: &disk, start, len };
    let container = Apfs::open(&part).unwrap();
    let summary: Vec<_> =
        container.volumes().into_iter().map(|v| (v.index, v.name.clone(), v.role_name(), v.encrypted)).collect();
    assert_eq!(
        summary,
        [
            (0, "Main".to_string(), "none", false),
            (1, "Second".to_string(), "data", false),
            (2, "Locked".to_string(), "none", true)
        ]
    );
    check(&container.volume(0).unwrap(), &truth("multi-main.tsv"), true, &[]);
    // diskutil mounted "Second" ignoring ownership, so stat's owners are not the stored ones.
    check(&container.volume(1).unwrap(), &truth("multi-second.tsv"), false, &[]);
    assert!(matches!(container.volume(2), Err(Error::Unsupported(m)) if m == "encrypted volume"));
    assert!(container.volume(3).is_err());
}

/// Opens, lists, walks and reads whatever the image allows; nothing may panic or hang.
/// Returns the number of nodes walked.
fn exercise(image: &dyn ReadAt) -> usize {
    let _ = apfs::probe(image);
    let Ok(container) = Apfs::open(image) else { return 0 };
    let mut walked = 0;
    for info in container.volumes() {
        let Ok(volume) = container.volume(info.index) else { continue };
        let mut files = Vec::new();
        let _ = volume.walk(
            &mut |n| {
                walked += 1;
                if n.kind == Kind::File && files.len() < 24 {
                    files.push((n.inode, n.size));
                }
            },
            &mut |_| {},
        );
        let mut buf = [0u8; 100];
        for (inode, size) in files {
            let _ = read_all(&volume, inode, size, 8 << 20);
            let _ = volume.read(inode, size / 2, &mut buf);
        }
    }
    walked
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

/// Damages a fixture's container `rounds` times (bit flips in metadata blocks, most of them
/// re-signed so they pass the checksum; zeroed metadata blocks) and truncates it `cuts` times.
/// Returns the slowest round and how many rounds walked part of the tree.
fn corrupt(name: &str, rounds: usize, cuts: usize, full: usize) -> (Duration, usize) {
    let (disk, start, len) = open_disk(name);
    let mut image = vec![0u8; len as usize];
    disk.read_at(start, &mut image).unwrap();
    // Metadata: every block that carries a valid object checksum.
    let meta: Vec<usize> = (0..image.len() / CHUNK)
        .filter(|&b| {
            let block = &image[b * CHUNK..(b + 1) * CHUNK];
            block.iter().any(|&x| x != 0)
                && u64::from_le_bytes(block[..8].try_into().unwrap()) == fletcher64(&block[8..])
        })
        .collect();
    assert!(meta.len() > 8, "{} metadata blocks", meta.len());

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    let (mut slowest, mut partial) = (Duration::ZERO, 0);
    let mut timed = |image: &dyn ReadAt| {
        let t = Instant::now();
        let walked = exercise(image);
        slowest = slowest.max(t.elapsed());
        partial += usize::from(walked > 0 && walked < full);
    };
    for round in 0..rounds {
        let block = meta[rand(meta.len())];
        let range = block * CHUNK..(block + 1) * CHUNK;
        let saved = image[range.clone()].to_vec();
        if round % 6 == 5 {
            image[range.clone()].fill(0);
        } else {
            for _ in 0..1 + rand(8) {
                // Mostly the header and table of contents, where the structure lives.
                let at = if rand(2) == 0 { rand(256) } else { rand(CHUNK) };
                image[block * CHUNK + at] ^= 1 << rand(8);
            }
            if round % 4 != 0 {
                let sum = fletcher64(&image[range.start + 8..range.end]);
                image[range.start..range.start + 8].copy_from_slice(&sum.to_le_bytes());
            }
        }
        timed(&Bytes(&image));
        image[range].copy_from_slice(&saved);
    }
    for i in 0..cuts {
        let cut = rand(image.len()) / (1 + i % 3);
        timed(&Bytes(&image[..cut]));
    }
    assert_eq!(exercise(&Bytes(&image)), full, "the restored image walks in full");
    (slowest, partial)
}

#[test]
fn corrupt_images_do_not_panic_or_hang() {
    let started = Instant::now();
    // The small volume makes rounds cheap; the large one has multi-level trees.
    let (slow_cs, partial_cs) = corrupt("cs.dmg.zst", 500, 60, 5);
    let (slow_basic, partial_basic) = corrupt("basic.dmg.zst", 220, 40, 3027 + 1);
    println!(
        "820 corruption rounds took {:?}; slowest {slow_cs:?} / {slow_basic:?}; partial walks {partial_cs} / {partial_basic}",
        started.elapsed()
    );
    assert!(slow_cs.max(slow_basic) < Duration::from_secs(10));
}

/// Walk speed on a large image: `APFS_BENCH_IMAGE=disk.dmg[.zst] cargo test --release -p
/// nixcavate-fs --test apfs walk_speed -- --ignored --nocapture`.
#[test]
#[ignore]
fn walk_speed() {
    let path = std::env::var("APFS_BENCH_IMAGE").expect("APFS_BENCH_IMAGE");
    let raw;
    let sparse;
    let disk: &dyn ReadAt = if path.ends_with(".zst") {
        sparse = Sparse::load(&path);
        &sparse
    } else {
        raw = std::fs::read(&path).unwrap();
        &Bytes(&raw)
    };
    let (start, len) = apfs_partition(disk);
    let part = Slice { inner: disk, start, len };
    let container = Apfs::open(&part).unwrap();
    let volume = container.volume(0).unwrap();
    let t = Instant::now();
    let (nodes, warnings) = walk(&volume);
    let secs = t.elapsed().as_secs_f64();
    assert!(warnings.is_empty(), "{warnings:?}");
    println!("{} nodes in {secs:.3} s: {:.0} files/s", nodes.len(), nodes.len() as f64 / secs);
}

/// SHA-256 (FIPS 180-4), to compare content with `shasum -a 256` without a dependency.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut s = h;
        for i in 0..64 {
            let s1 = s[4].rotate_right(6) ^ s[4].rotate_right(11) ^ s[4].rotate_right(25);
            let ch = (s[4] & s[5]) ^ (!s[4] & s[6]);
            let t1 = s[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = s[0].rotate_right(2) ^ s[0].rotate_right(13) ^ s[0].rotate_right(22);
            let maj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
            let t2 = s0.wrapping_add(maj);
            s = [t1.wrapping_add(t2), s[0], s[1], s[2], s[3].wrapping_add(t1), s[4], s[5], s[6]];
        }
        for (a, b) in h.iter_mut().zip(s) {
            *a = a.wrapping_add(b);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[test]
fn sha256_known_answer() {
    assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

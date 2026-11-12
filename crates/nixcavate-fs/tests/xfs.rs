//! XFS reader against real images built by `test_files/fs/xfs/build.sh`, compared with the
//! ground truth the real tools produced (stat or xfs_db, sha256sum, find).

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nixcavate_fs::xfs::{probe, Xfs};
use nixcavate_fs::{read_all, Bytes, Kind, Node, ReadAt, Volume};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/xfs").join(name)
}

fn unzstd(name: &str) -> Vec<u8> {
    let file = std::fs::File::open(fixture(name)).unwrap();
    zstd::stream::decode_all(file).unwrap()
}

fn text(name: &str) -> String {
    let bytes = if name.ends_with(".zst") { unzstd(name) } else { std::fs::read(fixture(name)).unwrap() };
    String::from_utf8(bytes).unwrap()
}

/// `seconds.nanoseconds` as printed by `stat %.9Y`; zero and `-` mean absent.
fn time(s: &str) -> Option<i64> {
    if s == "-" {
        return None;
    }
    let (sec, frac) = s.split_once('.').unwrap_or((s, "0"));
    let frac: i64 = format!("{frac:0<9}")[..9].parse().unwrap();
    let sec: i64 = sec.parse().unwrap();
    let ns = if s.starts_with('-') { sec * 1_000_000_000 - frac } else { sec * 1_000_000_000 + frac };
    (ns != 0).then_some(ns)
}

fn walk(fs: &Xfs<impl ReadAt>) -> (BTreeMap<String, Node>, Vec<String>) {
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

fn check_image(name: &str, has_crtime: bool) {
    let image = unzstd(&format!("{name}.img.zst"));
    let bytes = Bytes(&image);
    assert!(probe(&bytes));
    let fs = Xfs::open(&bytes).unwrap();
    assert_eq!(fs.kind(), "xfs");
    let (nodes, warnings) = walk(&fs);
    assert!(warnings.is_empty(), "{warnings:?}");

    let stat = text(&format!("{name}.stat.tsv.zst"));
    let mut expected = 0;
    for line in stat.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 11, "{line}");
        let node = nodes.get(f[0]).unwrap_or_else(|| panic!("{name}: {} not listed", f[0]));
        let mode = u32::from_str_radix(f[2], 16).unwrap();
        assert_eq!(node.inode, f[1].parse::<u64>().unwrap(), "{}", f[0]);
        assert_eq!(node.mode, mode, "{}", f[0]);
        assert_eq!(node.uid, f[3].parse::<u32>().unwrap(), "{}", f[0]);
        assert_eq!(node.gid, f[4].parse::<u32>().unwrap(), "{}", f[0]);
        assert_eq!(node.size, f[5].parse::<u64>().unwrap(), "{}", f[0]);
        assert_eq!(node.links, f[6].parse::<u32>().unwrap(), "{}", f[0]);
        assert_eq!(node.accessed, time(f[7]), "{} atime", f[0]);
        assert_eq!(node.modified, time(f[8]), "{} mtime", f[0]);
        assert_eq!(node.changed, time(f[9]), "{} ctime", f[0]);
        if has_crtime {
            assert!(time(f[10]).is_some());
        }
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
    assert_eq!(nodes.len(), expected, "{name}: extra paths listed");

    let mut files = 0;
    for line in text(&format!("{name}.sha256.zst")).lines() {
        let (hash, path) = line.split_once("  ").unwrap();
        let node = &nodes[path];
        let content = read_all(&fs, node.inode, node.size, 1 << 30).unwrap();
        assert_eq!(content.len() as u64, node.size, "{path}");
        assert_eq!(hex(&sha256(&content)), hash, "{name}: {path} content");
        files += 1;
    }
    assert!(files > 1000, "{name}: only {files} files checked");

    let links = text(&format!("{name}.links.tsv"));
    for line in links.lines() {
        let (path, target) = line.split_once('\t').unwrap();
        assert_eq!(nodes[path].link_target.as_deref(), Some(target), "{path}");
        let content = read_all(&fs, nodes[path].inode, target.len() as u64, 4096).unwrap();
        assert_eq!(content, target.as_bytes());
    }
    assert_eq!(links.lines().count(), 2);

    // Reads in odd-sized pieces at odd offsets match one whole read: holes, unwritten and
    // fragmented extents, block and AG boundaries.
    for path in ["sparse.bin", "fragmented.bin", "unwritten.bin", "a/b/large.bin"] {
        let Some(node) = nodes.get(path) else { continue };
        let whole = read_all(&fs, node.inode, node.size, 1 << 30).unwrap();
        let mut offset = 0usize;
        let mut piece = vec![0u8; 4093];
        while offset < whole.len() {
            let n = fs.read(node.inode, offset as u64, &mut piece).unwrap();
            assert!(n > 0);
            assert_eq!(&piece[..n], &whole[offset..offset + n], "{path} at {offset}");
            offset += n + 7919;
        }
        assert_eq!(fs.read(node.inode, node.size, &mut piece).unwrap(), 0);
    }
}

#[test]
fn v5_default_bigtime() {
    check_image("v5", true);
}

#[test]
fn v5_small_blocks_legacy_timestamps() {
    check_image("v5-1k", true);
}

#[test]
fn v4_no_ftype() {
    check_image("v4", false);
}

#[test]
fn bigtime_and_legacy_timestamps_outside_32_bits() {
    // Before 1970 in both; 2100 only representable with bigtime (legacy clamps to 2038).
    for (name, setuid_mtime) in [("v5", 4_102_444_800_500_000_000), ("v5-1k", 2_147_483_647_000_000_000)] {
        let image = unzstd(&format!("{name}.img.zst"));
        let bytes = Bytes(&image);
        let fs = Xfs::open(&bytes).unwrap();
        let (nodes, _) = walk(&fs);
        assert_eq!(nodes["a/b/c/d/e/deep.txt"].modified, Some(-302_443_200_000_000_000), "{name}");
        assert_eq!(nodes["a/setuid-bin"].modified, Some(setuid_mtime), "{name}");
        assert_eq!(nodes["a/setuid-bin"].mode, 0o104755);
        assert_eq!(nodes["small.txt"].modified, Some(981_173_106_123_456_789));
        assert_eq!(nodes["small.txt"].inode, nodes["a/hardlink.txt"].inode);
        assert_eq!(nodes["small.txt"].links, 2);
    }
}

/// `build-symlinks.sh`: with 1 KiB blocks a target longer than 968 bytes takes two blocks,
/// which are one extent with one header, not a header per block.
#[test]
fn remote_symlinks_longer_than_a_block() {
    let image = unzstd("symlinks-1k.img.zst");
    let fs = Xfs::open(Bytes(&image)).unwrap();
    let (nodes, warnings) = walk(&fs);
    assert!(warnings.is_empty(), "{warnings:?}");
    for n in [200usize, 968, 969, 1000, 1023] {
        let expected = String::from(char::from(b'a' + (n % 26) as u8)).repeat(n);
        let node = nodes.get(&format!("len{n}")).unwrap_or_else(|| panic!("len{n} is not listed"));
        assert_eq!(node.link_target.as_deref(), Some(expected.as_str()), "len{n}");
    }
}

#[test]
fn unwritten_extents_hide_old_data() {
    // unwritten.bin was preallocated over the blocks of a deleted file: the raw blocks still
    // hold that file's records, and the reader must return zeros instead.
    let image = unzstd("v5.img.zst");
    let bytes = Bytes(&image);
    let fs = Xfs::open(&bytes).unwrap();
    let (nodes, _) = walk(&fs);
    let node = &nodes["unwritten.bin"];
    let content = read_all(&fs, node.inode, node.size, 1 << 30).unwrap();
    assert!(content[..262144].iter().all(|&b| b == 0));
    assert!(content[262144..266240].iter().all(|&b| b == 0x7a));
    assert!(image.windows(14).any(|w| w == b"victim      00"), "victim data no longer in the image");
}

#[test]
fn rejects_non_xfs() {
    let zeros = vec![0u8; 1 << 16];
    assert!(!probe(&Bytes(&zeros)));
    assert!(Xfs::open(&Bytes(&zeros)).is_err());
    assert!(!probe(&Bytes(&[])));
}

/// A view of an image with some bytes replaced and an optional shorter length.
struct Damaged<'a> {
    base: &'a [u8],
    len: u64,
    patches: Vec<(u64, u8)>,
    zero: Option<(u64, u64)>,
}

impl ReadAt for Damaged<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.len);
        let Some(end) = end else { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "past end")) };
        buf.copy_from_slice(&self.base[offset as usize..end as usize]);
        for &(at, byte) in &self.patches {
            if at >= offset && at < end {
                buf[(at - offset) as usize] = byte;
            }
        }
        if let Some((zs, ze)) = self.zero {
            for at in zs.max(offset)..ze.min(end) {
                buf[(at - offset) as usize] = 0;
            }
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// Records the byte ranges a clean walk reads: the metadata worth damaging.
struct Recorder<'a> {
    base: Bytes<'a>,
    reads: Mutex<Vec<(u64, u64)>>,
}

impl ReadAt for Recorder<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.reads.lock().unwrap().push((offset, buf.len() as u64));
        self.base.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.base.size()
    }
}

/// Opens, walks and reads; must neither panic nor take long, whatever the outcome.
fn exercise(image: &dyn ReadAt) {
    let start = Instant::now();
    if let Ok(fs) = Xfs::open(image) {
        let mut nodes = Vec::new();
        let _ = fs.walk(&mut |n| nodes.push((n.inode, n.size)), &mut |_| {});
        let mut buf = vec![0u8; 1 << 16];
        for &(inode, _) in nodes.iter().take(64) {
            let _ = fs.read(inode, 0, &mut buf);
        }
        for &(inode, size) in nodes.iter().filter(|n| n.1 < 1 << 22).take(8) {
            let _ = read_all(&fs, inode, size, 1 << 22);
        }
    }
    assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
}

fn corruption_run(name: &str) {
    let image = unzstd(&format!("{name}.img.zst"));
    let recorder = Recorder { base: Bytes(&image), reads: Mutex::new(Vec::new()) };
    {
        let fs = Xfs::open(&recorder).unwrap();
        fs.walk(&mut |_| {}, &mut |_| {}).unwrap();
    }
    let mut regions = recorder.reads.into_inner().unwrap();
    regions.retain(|&(_, len)| len <= 65536);
    regions.sort_unstable();
    regions.dedup();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let len = image.len() as u64;
    let block = 4096u64;
    for round in 0..600 {
        let mut damaged = Damaged { base: &image, len, patches: Vec::new(), zero: None };
        match round % 4 {
            // Byte flips inside metadata the walk reads, including the superblock.
            0 | 1 => {
                for _ in 0..1 + next() % 16 {
                    let (start, rlen) = regions[(next() % regions.len() as u64) as usize];
                    let at = start + next() % rlen;
                    let at = if next() % 8 == 0 { next() % 512 } else { at };
                    damaged.patches.push((at, (next() & 0xff) as u8));
                }
            }
            // A zeroed metadata block.
            2 => {
                let (start, _) = regions[(next() % regions.len() as u64) as usize];
                let zs = start / block * block;
                damaged.zero = Some((zs, zs + block));
            }
            // Truncation, mostly inside the metadata area.
            _ => {
                let (start, rlen) = regions[(next() % regions.len() as u64) as usize];
                damaged.len = (start + next() % (rlen + 1)).min(len);
            }
        }
        exercise(&damaged);
    }
    for cut in [0, 1, 100, 511, 512, 4096, 65536, 1 << 20, len / 2, len - 1] {
        exercise(&Damaged { base: &image, len: cut, patches: Vec::new(), zero: None });
    }
}

#[test]
fn corrupted_v5_images_never_panic_or_hang() {
    corruption_run("v5");
}

#[test]
fn corrupted_v5_1k_images_never_panic_or_hang() {
    corruption_run("v5-1k");
}

#[test]
fn corrupted_v4_images_never_panic_or_hang() {
    corruption_run("v4");
}

/// Walk speed on a large image outside the repository:
/// `XFS_BENCH_IMAGE=/path/to.img cargo test --release -p nixcavate-fs --test xfs -- --ignored`
#[test]
#[ignore]
fn bench_walk() {
    let path = std::env::var("XFS_BENCH_IMAGE").expect("set XFS_BENCH_IMAGE");
    let image = std::fs::read(path).unwrap();
    let bytes = Bytes(&image);
    let fs = Xfs::open(&bytes).unwrap();
    let start = Instant::now();
    let mut count = 0u64;
    let mut kinds: HashMap<String, u64> = HashMap::new();
    fs.walk(
        &mut |n| {
            count += 1;
            *kinds.entry(format!("{:?}", n.kind)).or_default() += 1;
        },
        &mut |w| eprintln!("warning: {w}"),
    )
    .unwrap();
    let elapsed = start.elapsed();
    eprintln!("{count} nodes in {elapsed:?}: {:.0} nodes/s {kinds:?}", count as f64 / elapsed.as_secs_f64());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 (FIPS 180-4), to compare contents with `sha256sum` without a dependency.
fn sha256(data: &[u8]) -> [u8; 32] {
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
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

//! UFS1/UFS2 reader against real images built by `test_files/fs/ufs/build.sh` in FreeBSD.
//!
//! Ground truth (`NAME.truth.zst`, `NAME.sha256`) was written by FreeBSD's `stat` and
//! `sha256sum` while each image was mounted by the FreeBSD kernel; the big-endian `makefs`
//! images share the truth of their little-endian twin. Also here: damaged and crafted images
//! (byte flips, truncation, boundary values in every metadata field, loops) that must not
//! panic, hang or report an outsized walk.

use std::collections::{HashMap, HashSet};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nixcavate_fs::ufs::{self, Ufs};
use nixcavate_fs::{read_all, Bytes, Kind, Node, ReadAt, Volume};
use sha2::{Digest, Sha256};

fn fixture(file: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/ufs").join(file);
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

/// `stat -f %.9Fm` seconds to nanoseconds; zero is "no time", and so is UFS1's birth time of -1.
fn nanos(field: &str) -> Option<i64> {
    let (secs, frac) = field.split_once('.').unwrap_or((field, "0"));
    let negative = secs.starts_with('-');
    let secs: i64 = secs.parse().unwrap();
    let frac: i64 = format!("{frac:0<9}")[..9].parse().unwrap();
    let ns = secs * 1_000_000_000 + if negative { -frac } else { frac };
    (ns != 0 && ns != -1_000_000_000).then_some(ns)
}

/// A name as FreeBSD's `sha256sum` writes it: other than printable ASCII as `\NNN` octal
/// escapes, and `\` before shell metacharacters.
fn unescape(name: &str) -> String {
    let b = name.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push(u8::from_str_radix(&name[i + 1..i + 4], 8).unwrap());
            i += 4;
        } else if b[i] == b'\\' && i + 1 < b.len() {
            out.push(b[i + 1]);
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// SHA-256 of a whole file, read 1 MiB at a time.
fn digest(volume: &dyn Volume, node: &Node) -> String {
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0;
    while at < node.size {
        let n = volume.read(node.inode, at, &mut buf).unwrap();
        assert!(n > 0, "{}: short read at {at}", node.path);
        hash.update(&buf[..n]);
        at += n as u64;
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads `want.len()` bytes at `at` and compares them.
fn read_at(volume: &dyn Volume, node: &Node, at: u64, want: &[u8]) {
    let mut buf = vec![0xAAu8; want.len()];
    assert_eq!(volume.read(node.inode, at, &mut buf).unwrap(), want.len(), "{}", node.path);
    assert_eq!(buf, want, "{} at {at}", node.path);
}

/// What a comparison with the truth found.
#[derive(Default)]
struct Outcome {
    warnings: Vec<String>,
    /// Fields that differ from the truth: `path: field: ours != truth`.
    differences: Vec<String>,
    /// UFS1 times later than when the truth was taken, which FreeBSD shows as that time.
    clamped: Vec<String>,
}

/// Compares the walk with the stat listing and every file's content with sha256sum.
fn check_against_truth(name: &str, truth: &str, ufs2: bool) -> Outcome {
    let data = image(name);
    let bytes = Bytes(&data);
    assert!(ufs::probe(&bytes), "{name}");
    let volume = Ufs::open(&bytes).unwrap();
    assert_eq!(volume.kind(), "ufs");
    let (nodes, warnings) = walk(&volume);
    let mut out = Outcome { warnings, ..Outcome::default() };
    let solaris = name.starts_with("sol-");
    let mut by_path = HashMap::new();
    for node in nodes {
        let path = node.path.clone();
        assert!(by_path.insert(path.clone(), node).is_none(), "{name}: {path} listed twice");
    }

    let listing = zstd::decode_all(&fixture(&format!("{truth}.truth.zst"))[..]).unwrap();
    let lines: Vec<Vec<String>> = listing
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| String::from_utf8_lossy(l).split('\t').map(str::to_string).collect())
        .collect();
    // When the listing was taken: its newest change time.
    let taken = lines.iter().filter_map(|f| nanos(&f[9])).max().unwrap();
    for f in &lines {
        assert_eq!(f.len(), 12, "{f:?}");
        let Some(node) = by_path.get(&f[0]) else {
            out.differences.push(format!("{}: missing from the walk", f[0]));
            continue;
        };
        let mode = u32::from_str_radix(&f[1], 16).unwrap();
        let kind = match mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Directory,
            0o120000 => Kind::Symlink,
            _ => Kind::Other,
        };
        let mut differ = |field: &str, ours: String, theirs: &str| {
            if ours != theirs {
                out.differences.push(format!("{}: {field}: {ours} != {theirs}", f[0]));
            }
        };
        differ("mode", node.mode.to_string(), &mode.to_string());
        differ("kind", format!("{:?}", node.kind), &format!("{kind:?}"));
        differ("inode", node.inode.to_string(), &f[2]);
        differ("links", node.links.to_string(), &f[3]);
        // illumos's `stat` of a device node shows the device (specfs): its size, and its times
        // to the second. The inode keeps the times to the microsecond.
        let device = solaris && kind == Kind::Other && mode & 0o170000 != 0o010000;
        if !device {
            differ("size", node.size.to_string(), &f[4]);
        }
        differ("uid", node.uid.to_string(), &f[5]);
        differ("gid", node.gid.to_string(), &f[6]);
        let target = if kind == Kind::Symlink { Some(f[11].as_str()) } else { None };
        differ("target", format!("{:?}", node.link_target.as_deref()), &format!("{target:?}"));
        for (field, ours, theirs) in [
            ("atime", node.accessed, nanos(&f[7])),
            ("mtime", node.modified, nanos(&f[8])),
            ("ctime", node.changed, nanos(&f[9])),
            ("birthtime", node.created, nanos(&f[10])),
        ] {
            let later = ours.zip(theirs).is_some_and(|(o, t)| o > taken && t <= taken + 60_000_000_000);
            let ours = if device { ours.map(|t| t.div_euclid(1_000_000_000) * 1_000_000_000) } else { ours };
            if !ufs2 && !solaris && later {
                out.clamped.push(format!("{}: {field}", f[0]));
            } else {
                differ(field, format!("{ours:?}"), &format!("{theirs:?}"));
            }
        }
        if node.created.is_some() != ufs2 {
            out.differences.push(format!("{}: birthtime present: {}", f[0], node.created.is_some()));
        }
    }
    let listed: HashSet<&str> = lines.iter().map(|f| f[0].as_str()).collect();
    for path in by_path.keys().filter(|p| !listed.contains(p.as_str())) {
        out.differences.push(format!("{path}: not listed by stat"));
    }

    // Content: every non-empty regular file under 300 MiB has a digest.
    let sums = String::from_utf8_lossy(&fixture(&format!("{truth}.sha256"))).into_owned();
    let sums: HashMap<String, &str> = sums
        .lines()
        .map(|l| match l.strip_prefix('\\') {
            // GNU `sha256sum` (the illumos images) marks a line whose name it escaped.
            Some(l) => (l[66..].replace("\\\\", "\\").replace("\\n", "\n"), &l[..64]),
            None if solaris => (l[66..].to_string(), &l[..64]),
            None => (unescape(&l[66..]), &l[..64]),
        })
        .collect();
    let mut hashed = 0;
    for node in by_path.values().filter(|n| n.kind == Kind::File && n.size > 0 && n.size < 300 << 20) {
        let Some(expected) = sums.get(&node.path) else {
            out.differences.push(format!("{}: no digest", node.path));
            continue;
        };
        hashed += 1;
        // The journal is written to until the unmount, after the digests were taken.
        if node.path != ".sujournal" && digest(&volume, node) != *expected {
            out.differences.push(format!("{}: content", node.path));
        }
    }
    if sums.len() != hashed {
        out.differences.push(format!("{} digests, {hashed} files hashed", sums.len()));
    }
    if !out.differences.is_empty() {
        return out;
    }
    let empty = &by_path["big/size0"];
    assert!(read_all(&volume, empty.inode, empty.size, 1 << 20).unwrap().is_empty());

    // Targeted reads at the indirect blocks and in holes, whatever the files' sizes.
    let ind1 = &by_path["big/ind1"];
    let bs = (ind1.size - 3) / 12;
    read_at(&volume, ind1, 0, b"start\0");
    read_at(&volume, ind1, ind1.size - 4, b"\0one");
    if let Some(ind2) = by_path.get("big/ind2") {
        read_at(&volume, ind2, ind2.size - 9, b"\0\0\0\0\0\0two");
        let ind3 = &by_path["big/ind3"];
        read_at(&volume, ind3, ind3.size - 6, b"\0three");
        read_at(&volume, ind3, ind3.size / 2, &[0; 4096]);
        let mut buf = [0u8; 8];
        assert_eq!(volume.read(ind3.inode, ind3.size, &mut buf).unwrap(), 0);
    }
    let sparse = &by_path["big/sparse"];
    read_at(&volume, sparse, 5 * bs + 98, b"\0\0middle\0");
    read_at(&volume, sparse, 40 * bs, b"end");
    // (The copy taken while mounted does not have them yet.)
    for special in ["special/fifo", "special/char"].iter().filter_map(|p| by_path.get(*p)) {
        assert!(volume.read(special.inode, 0, &mut [0u8; 8]).is_err(), "{}", special.path);
    }
    out
}

/// No warnings, no differences and no times FreeBSD shows differently.
fn exact(name: &str, truth: &str, ufs2: bool) {
    let out = check_against_truth(name, truth, ufs2);
    assert!(out.warnings.is_empty(), "{name}: {:?}", out.warnings);
    assert!(out.differences.is_empty(), "{name}: {:?}", out.differences);
    assert!(out.clamped.is_empty(), "{name}: {:?}", out.clamped);
}

#[test]
fn ufs2_default() {
    exact("ufs2", "ufs2", true);
}

#[test]
fn ufs2_4k_blocks_512_byte_fragments() {
    exact("ufs2-4k", "ufs2-4k", true);
}

#[test]
fn ufs2_64k_blocks() {
    exact("ufs2-64k", "ufs2-64k", true);
}

/// UFS1 keeps 32-bit times, which FreeBSD reads as unsigned (1970 to 2106): 1960 and 2200 wrap.
#[test]
fn ufs1_8k_blocks() {
    exact("ufs1", "ufs1", false);
}

#[test]
fn ufs2_soft_updates_journal() {
    exact("ufs2-suj", "ufs2-suj", true);
}

/// When FreeBSD 14 loads a UFS1 inode whose time is later than the present, it shows the
/// present instead (the files of `ufs1` above were listed before their inodes were ever
/// loaded from disk). The reader reports what is stored: here the 1960, 2040 and 2200 times.
fn makefs_ufs1(name: &str) {
    let out = check_against_truth(name, "mk1-le", false);
    assert!(out.warnings.is_empty() && out.differences.is_empty(), "{name}: {:?} {:?}", out.warnings, out.differences);
    let mut clamped = out.clamped;
    clamped.sort();
    let want: Vec<String> = ["y1960", "y2040", "y2200"]
        .iter()
        .flat_map(|f| [format!("times/{f}: atime"), format!("times/{f}: mtime")])
        .collect();
    assert_eq!(clamped, want, "{name}");
}

#[test]
fn makefs_little_endian() {
    exact("mk2-le", "mk2-le", true);
    makefs_ufs1("mk1-le");
}

/// The big-endian images are the same trees laid out the same way in the other byte order.
#[test]
fn makefs_big_endian() {
    exact("mk2-be", "mk2-le", true);
    makefs_ufs1("mk1-be");
}

/// Solaris UFS made by illumos (OmniOS): owners in other fields, microsecond times, the old
/// directory format, a log in the filesystem. Cleanly unmounted, with and without logging.
#[test]
fn solaris_ufs() {
    exact("sol-ufs", "sol-ufs", false);
    exact("sol-nologging", "sol-nologging", false);
}

/// A Solaris logging UFS copied while mounted: the log is not rolled, which one warning says.
/// (`lockfs -w` before the copy flushed the files, so the listing still matches the mount.)
#[test]
fn solaris_log_not_rolled() {
    let out = check_against_truth("sol-dirty", "sol-dirty", false);
    assert!(out.differences.is_empty() && out.clamped.is_empty(), "{:?}", out.differences);
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].contains("UFS log is not rolled"), "{:?}", out.warnings);
}

/// Copied while mounted (soft updates with journal): read as it is on disk, with one warning.
/// The truth is FreeBSD's read-only mount of the copy, which does not replay the journal either;
/// the copy lacks the last seconds of changes the live mount showed (the second half of the
/// tree), as any image of a mounted filesystem does.
#[test]
fn imaged_while_mounted() {
    let out = check_against_truth("dirty", "dirty", true);
    let warnings = out.warnings;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("not cleanly unmounted") && warnings[0].contains("journal"), "{warnings:?}");
    assert!(out.differences.is_empty(), "{:?}", out.differences);
    assert!(out.clamped.is_empty());
}

#[test]
fn not_ufs() {
    let zeros = vec![0u8; 300 << 10];
    assert!(!ufs::probe(&Bytes(&zeros)));
    assert!(Ufs::open(&Bytes(&zeros)).is_err());
    assert!(!ufs::probe(&Bytes(&[])));
}

// ---------------------------------------------------------------------------------------
// Layout helpers for crafting damaged images (little-endian fixtures).

fn get32(d: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(d[at..at + 4].try_into().unwrap()))
}

fn get64(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}

fn put16(d: &mut [u8], at: usize, v: u16) {
    d[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(d: &mut [u8], at: usize, v: u64) {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

struct Layout {
    sb: usize,
    ufs2: bool,
    bs: usize,
    fs: usize,
    ipg: usize,
    fpg: usize,
    iblkno: usize,
    cblkno: usize,
    isz: usize,
}

impl Layout {
    fn of(d: &[u8]) -> Layout {
        let sb = [65536, 8192]
            .into_iter()
            .find(|&at| get32(d, at + 1372) & 0xffff == 0x1954 || get32(d, at + 1372) == 0x1954_0119)
            .unwrap();
        let ufs2 = get32(d, sb + 1372) == 0x1954_0119;
        Layout {
            sb,
            ufs2,
            bs: get32(d, sb + 48) as usize,
            fs: get32(d, sb + 52) as usize,
            ipg: get32(d, sb + 184) as usize,
            fpg: get32(d, sb + 188) as usize,
            iblkno: get32(d, sb + 16) as usize,
            cblkno: get32(d, sb + 12) as usize,
            isz: if ufs2 { 256 } else { 128 },
        }
    }

    /// Byte offset of inode `ino` (UFS1 fixtures here have no cylinder-group rotation).
    fn inode(&self, ino: usize) -> usize {
        let (c, i) = (ino / self.ipg, ino % self.ipg);
        (c * self.fpg + self.iblkno) * self.fs + i * self.isz
    }

    fn cg(&self, c: usize) -> usize {
        (c * self.fpg + self.cblkno) * self.fs
    }

    /// Offset of direct pointer `i` (12 to 14 are the indirect ones) in the inode at `at`.
    fn ptr(&self, at: usize, i: usize) -> usize {
        if self.ufs2 {
            at + 112 + 8 * i
        } else {
            at + 40 + 4 * i
        }
    }

    fn get_ptr(&self, d: &[u8], at: usize, i: usize) -> usize {
        (if self.ufs2 { get64(d, self.ptr(at, i)) } else { get32(d, self.ptr(at, i)) }) as usize
    }

    fn set_ptr(&self, d: &mut [u8], at: usize, v: u64) {
        if self.ufs2 {
            put64(d, at, v);
        } else {
            put32(d, at, v as u32);
        }
    }

    /// The byte offset of the first block of the root directory.
    fn root_block(&self, d: &[u8]) -> usize {
        self.get_ptr(d, self.inode(2), 0) * self.fs
    }
}

/// Offset of the root-directory entry whose name is `name`.
fn root_entry(d: &[u8], lay: &Layout, name: &[u8]) -> usize {
    let block = lay.root_block(d);
    let mut off = 0;
    while off < 512 {
        let reclen = u16::from_le_bytes([d[block + off + 4], d[block + off + 5]]) as usize;
        let namlen = d[block + off + 7] as usize;
        if &d[block + off + 8..block + off + 8 + namlen] == name {
            return block + off;
        }
        off += reclen;
    }
    panic!("no root entry {name:?}");
}

/// The inode number of root entry `name`.
fn root_child(d: &[u8], lay: &Layout, name: &[u8]) -> usize {
    get32(d, root_entry(d, lay, name)) as usize
}

fn walk_any(volume: &dyn Volume) -> (Vec<Node>, Vec<String>) {
    let (mut nodes, mut warnings) = (Vec::new(), Vec::new());
    let _ = volume.walk(&mut |n| nodes.push(n), &mut |w| warnings.push(w));
    (nodes, warnings)
}

/// Counts reads and fails every read after `limit`, so a runaway walk ends quickly.
struct Counting<'a> {
    inner: Bytes<'a>,
    reads: std::sync::atomic::AtomicU64,
}

impl ReadAt for Counting<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if self.reads.fetch_add(1, Ordering::Relaxed) >= 1_000_000 {
            return Err(io::Error::other("read limit of the test reached"));
        }
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

// ---------------------------------------------------------------------------------------
// Crafted damage.

#[test]
fn an_indirect_block_that_points_to_itself_ends() {
    for name in ["ufs2", "ufs1"] {
        let mut d = image(name);
        let lay = Layout::of(&d);
        // `frag/a` is 40 blocks: its single indirect block names itself in every slot.
        let (nodes, _) = walk(&Ufs::open(&Bytes(&d)).unwrap());
        let a = nodes.iter().find(|n| n.path == "frag/a").unwrap();
        let at = lay.inode(a.inode as usize);
        let ind = lay.get_ptr(&d, at, 12);
        let width = if lay.ufs2 { 8 } else { 4 };
        for i in 0..lay.bs / width {
            lay.set_ptr(&mut d, ind * lay.fs + i * width, ind as u64);
        }
        // The double-indirect pointer names it too, and the size claims the largest file.
        lay.set_ptr(&mut d, lay.ptr(at, 13), ind as u64);
        lay.set_ptr(&mut d, lay.ptr(at, 14), ind as u64);
        let size_at = if lay.ufs2 { at + 16 } else { at + 8 };
        put64(&mut d, size_at, 1 << 40);
        let image = Counting { inner: Bytes(&d), reads: 0.into() };
        let volume = Ufs::open(&image).unwrap();
        let start = Instant::now();
        let mut buf = vec![0u8; 1 << 20];
        for offset in [0, 13 * lay.bs as u64, 5000 * lay.bs as u64, 1 << 30, (1 << 40) - 10] {
            // The data is whatever the loop names: the point is that it ends.
            let _ = volume.read(a.inode, offset, &mut buf);
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{name}: {:?}", start.elapsed());
    }
}

#[test]
fn a_directory_record_of_length_zero_is_damage_not_a_loop() {
    let mut d = image("ufs2");
    let lay = Layout::of(&d);
    let entry = root_entry(&d, &lay, b"etc");
    put16(&mut d, entry + 4, 0);
    let (nodes, warnings) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    assert!(warnings.iter().any(|w| w.contains("damaged 512-byte chunks")), "{warnings:?}");
    assert!(!nodes.is_empty());
}

#[test]
fn a_directory_that_contains_its_parent_is_listed_once() {
    let mut d = image("ufs1");
    let lay = Layout::of(&d);
    // `etc` now names the root directory.
    let entry = root_entry(&d, &lay, b"etc");
    put32(&mut d, entry, 2);
    let clean = walk(&Ufs::open(&Bytes(&image("ufs1"))).unwrap()).0.len();
    let (nodes, warnings) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    assert!(nodes.len() < clean);
    assert!(warnings.iter().any(|w| w.contains("already")), "{warnings:?}");
}

#[test]
fn shared_directory_blocks_are_read_once() {
    let mut d = image("ufs2");
    let lay = Layout::of(&d);
    let (nodes, _) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    let clean = nodes.len();
    let many = nodes.iter().find(|n| n.path == "manyfiles").unwrap();
    let at = lay.inode(many.inode as usize);
    let first = lay.get_ptr(&d, at, 0) as u64;
    // Every direct pointer of every directory names manyfiles' first block.
    for dir in nodes.iter().filter(|n| n.kind == Kind::Directory) {
        let at = lay.inode(dir.inode as usize);
        for i in 0..12 {
            lay.set_ptr(&mut d, lay.ptr(at, i), first);
        }
        put64(&mut d, at + 16, 12 * lay.bs as u64);
    }
    let (nodes, warnings) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    assert!(nodes.len() <= clean);
    let paths: HashSet<&str> = nodes.iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths.len(), nodes.len());
    assert!(warnings.iter().any(|w| w.contains("already read")), "{warnings:?}");
}

/// A directory claiming a petabyte: its block map is holes after the real blocks, and a hole
/// ends the listing instead of being walked.
#[test]
fn a_directory_with_a_forged_size_ends_at_its_first_hole() {
    for name in ["ufs2-64k", "ufs1"] {
        let mut d = image(name);
        let lay = Layout::of(&d);
        let (nodes, _) = walk(&Ufs::open(&Bytes(&d)).unwrap());
        let many = nodes.iter().find(|n| n.path == "manyfiles").unwrap();
        let at = lay.inode(many.inode as usize);
        put64(&mut d, if lay.ufs2 { at + 16 } else { at + 8 }, 1 << 50);
        let start = Instant::now();
        let (after, warnings) = walk(&Ufs::open(&Bytes(&d)).unwrap());
        assert!(start.elapsed() < Duration::from_secs(2), "{name}: {:?}", start.elapsed());
        // The last real block is now read whole, past its fragments: what follows them may
        // parse as a few more entries.
        assert!(after.len() < nodes.len() + 100, "{name}: {} nodes", after.len());
        assert!(warnings.iter().any(|w| w.contains("/manyfiles: hole at directory block")), "{warnings:?}");
    }
}

#[test]
fn pointers_past_the_end_are_errors() {
    let mut d = image("ufs2");
    let lay = Layout::of(&d);
    let (nodes, _) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    let file = nodes.iter().find(|n| n.path == "frag/a").unwrap();
    let at = lay.inode(file.inode as usize);
    for (slot, value) in [(0, u64::MAX), (1, 1 << 62), (12, u64::MAX / 4096 + 1)] {
        lay.set_ptr(&mut d, lay.ptr(at, slot), value);
    }
    let volume = Ufs::open(Bytes(&d)).unwrap();
    let mut buf = vec![0u8; 64 << 10];
    assert!(volume.read(file.inode, 0, &mut buf).is_err());
    assert!(volume.read(file.inode, 12 * lay.bs as u64, &mut buf).is_err());
    for ino in [0, 1, u64::from(u32::MAX), u64::MAX] {
        let _ = volume.read(ino, 0, &mut buf);
    }
}

#[test]
fn inodes_past_cg_initediblk_are_not_read() {
    let mut d = image("ufs2");
    let lay = Layout::of(&d);
    let file = root_child(&d, &lay, b"etc");
    // Group 0 claims none of its inodes were initialised past the root's neighbours.
    put32(&mut d, lay.cg(0) + 120, 3);
    let (nodes, warnings) = walk(&Ufs::open(&Bytes(&d)).unwrap());
    assert!(nodes.iter().all(|n| n.inode < 3 || n.inode as usize >= lay.ipg), "{file}");
    assert!(warnings.iter().any(|w| w.contains("never initialised")), "{warnings:?}");
    // A damaged group header refuses its inodes: here the root's, so the volume does not open.
    put32(&mut d, lay.cg(0) + 4, 0);
    assert!(Ufs::open(&Bytes(&d)).is_err());
}

#[test]
fn forged_geometry_is_refused() {
    let base = image("ufs2");
    let lay = Layout::of(&base);
    let sb = lay.sb;
    for (at, value) in [
        (48, 1u32 << 30), // fs_bsize
        (48, 0),
        (52, 3),         // fs_fsize
        (56, 64),        // fs_frag
        (184, u32::MAX), // fs_ipg
        (188, u32::MAX), // fs_fpg
        (44, u32::MAX),  // fs_ncg
        (16, u32::MAX),  // fs_iblkno
        (120, 1),        // fs_inopb
    ] {
        let mut d = base.clone();
        put32(&mut d, sb + at, value);
        assert!(Ufs::open(&Bytes(&d)).is_err(), "field {at} = {value:#x}");
    }
    // A backup superblock (another location recorded) is not taken for the primary.
    let mut d = base.clone();
    put64(&mut d, sb + 1000, 8192);
    assert!(Ufs::open(&Bytes(&d)).is_err());
}

/// Old filesystems (4.2BSD format, Solaris): a 16-bit name length in the directory records and
/// short symlinks known by having no blocks. Here the root directory of a UFS1 image is
/// rewritten in that format and `fs_maxsymlinklen` cleared.
#[test]
fn old_format_directories() {
    let clean = image("ufs1");
    let lay = Layout::of(&clean);
    let mut d = clean.clone();
    put32(&mut d, lay.sb + 1320, 0);
    let root = lay.inode(2);
    let size = get64(&d, root + 8) as usize;
    let block = lay.root_block(&d);
    for chunk in (block..block + size).step_by(512) {
        let mut off = 0;
        while off < 512 {
            let reclen = u16::from_le_bytes([d[chunk + off + 4], d[chunk + off + 5]]) as usize;
            let namlen = d[chunk + off + 7];
            put16(&mut d, chunk + off + 6, u16::from(namlen));
            off += reclen;
        }
    }
    let top = |nodes: &[Node]| {
        let mut v: Vec<(String, u64)> =
            nodes.iter().filter(|n| !n.path.contains('/')).map(|n| (n.path.clone(), n.inode)).collect();
        v.sort();
        v
    };
    let want = top(&walk(&Ufs::open(&Bytes(&clean)).unwrap()).0);
    let (nodes, _) = walk_any(&Ufs::open(&Bytes(&d)).unwrap());
    assert_eq!(top(&nodes), want);
    // The other directories are still in the new format, which this filesystem now says it
    // does not use: they are damage, reported, not misread names.
    assert!(nodes.iter().filter(|n| n.path.contains('/')).all(|n| n.path.is_ascii()));
}

// ---------------------------------------------------------------------------------------
// Byte flips, truncation and boundary values.

/// Opens, walks and reads a damaged image; returns the number of nodes walked.
fn exercise(image: &dyn ReadAt) -> usize {
    let Ok(volume) = Ufs::open(image) else { return 0 };
    let mut nodes = Vec::new();
    let mut count = 0;
    let _ = volume.walk(
        &mut |n| {
            count += 1;
            if nodes.len() < 300 && matches!(n.kind, Kind::File | Kind::Symlink) {
                nodes.push(n);
            }
        },
        &mut |_| {},
    );
    let mut buf = vec![0u8; 64 << 10];
    for n in &nodes {
        let _ = volume.read(n.inode, 0, &mut buf);
        let _ = volume.read(n.inode, n.size.saturating_sub(10), &mut buf);
        let _ = read_all(&volume, n.inode, n.size, 4 << 20);
    }
    for ino in [0, 1, 2, 3, u64::from(u32::MAX), u64::MAX] {
        let _ = volume.read(ino, 0, &mut buf);
    }
    count
}

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

/// Runs `cases` (byte strings written at an offset) on all cores; none may panic, take over
/// 10 s or walk more than 100 000 nodes.
fn run_cases(name: &str, base: &[u8], cases: &[(usize, Vec<u8>)]) {
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let started = Instant::now();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while let Some((at, bytes)) = cases.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let image = Patched { base, at: *at, bytes };
                    let t = Instant::now();
                    let result = catch_unwind(AssertUnwindSafe(|| exercise(&image)));
                    let failure = match result {
                        Err(_) => Some("panicked".to_string()),
                        Ok(_) if t.elapsed() > Duration::from_secs(10) => Some(format!("took {:?}", t.elapsed())),
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
    println!("{name}: {} cases in {:?}", cases.len(), started.elapsed());
    assert!(failures.is_empty(), "{} failures, first: {:?}", failures.len(), &failures[..failures.len().min(20)]);
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

/// Metadata of a fixture: the superblock, cylinder group 0's header, the first inodes of every
/// group, and every non-zero fragment that is a directory or indirect block of a walked file.
fn metadata_regions(d: &[u8]) -> Vec<(usize, usize)> {
    let lay = Layout::of(d);
    let ncg = get32(d, lay.sb + 44) as usize;
    let mut regions = vec![(lay.sb, lay.sb + 1376), (lay.cg(0), lay.cg(0) + 256)];
    for c in 0..ncg {
        let first = lay.inode(c * lay.ipg);
        regions.push((first, first + 64 * lay.isz));
    }
    let (nodes, _) = walk(&Ufs::open(&Bytes(d)).unwrap());
    for n in nodes.iter().filter(|n| n.kind == Kind::Directory || n.size > 12 * lay.bs as u64).take(200) {
        let at = lay.inode(n.inode as usize);
        let ptrs = if n.kind == Kind::Directory { 0..1 } else { 12..15 };
        for i in ptrs {
            let p = lay.get_ptr(d, at, i) * lay.fs;
            if p != 0 && p + lay.bs <= d.len() {
                regions.push((p, p + lay.bs.min(4096)));
            }
        }
    }
    regions
}

fn corrupt_many(name: &str, seed: u64, rounds: usize) {
    let clean = image(name);
    let regions = metadata_regions(&clean);
    let mut rng = Rng(seed);
    let mut cases = Vec::new();
    for _ in 0..rounds {
        // One to eight flips; the superblock and group header are hit most often.
        let pick = if rng.below(2) == 0 { rng.below(2) } else { rng.below(regions.len()) };
        let (start, end) = regions[pick];
        let at = start + rng.below(end - start - 8);
        let mut bytes = clean[at..at + 8].to_vec();
        for _ in 0..1 + rng.below(8) {
            let i = rng.below(8);
            bytes[i] ^= 1 << rng.below(8);
            if rng.below(4) == 0 {
                bytes[i] = [0, 0xFF, 0x80, 0x7F][rng.below(4)];
            }
        }
        cases.push((at, bytes));
    }
    // Zeroed regions.
    for &(start, end) in regions.iter().take(rounds / 4) {
        cases.push((start, vec![0u8; end - start]));
    }
    run_cases(name, &clean, &cases);
    // Truncation at many lengths.
    for _ in 0..rounds / 8 {
        let len = rng.below(clean.len());
        let t = Instant::now();
        exercise(&Bytes(&clean[..len]));
        assert!(t.elapsed() < Duration::from_secs(10), "{name} truncated to {len}");
    }
}

#[test]
fn damaged_ufs2() {
    corrupt_many("ufs2", 0x9E37_79B9_7F4A_7C15, 800);
}

#[test]
fn damaged_ufs1() {
    corrupt_many("ufs1", 0xD1B5_4A32_D192_ED03, 800);
}

#[test]
fn damaged_solaris() {
    corrupt_many("sol-ufs", 0x1D8E_4E27_C47D_124F, 500);
}

#[test]
fn damaged_big_endian() {
    corrupt_many_be("mk2-be", 0x2545_F491_4F6C_DD1D, 500);
}

/// The big-endian image: flips anywhere in its non-zero fragments.
fn corrupt_many_be(name: &str, seed: u64, rounds: usize) {
    let clean = image(name);
    let used: Vec<usize> =
        (0..clean.len() / 4096).filter(|&i| clean[i * 4096..(i + 1) * 4096].iter().any(|&b| b != 0)).collect();
    let mut rng = Rng(seed);
    let mut cases = Vec::new();
    for _ in 0..rounds {
        let block = if rng.below(2) == 0 { 16 } else { used[rng.below(used.len())] };
        let at = block * 4096 + rng.below(4096 - 8);
        let mut bytes = clean[at..at + 8].to_vec();
        let i = rng.below(8);
        bytes[i] = [0, 0xFF, 0x80, 0x7F, bytes[i] ^ 1][rng.below(5)];
        cases.push((at, bytes));
    }
    run_cases(name, &clean, &cases);
}

/// Boundary values (0, 1, 0x7f, 0x80, 0xff, ... u64::MAX) as 1-, 2-, 4- and 8-byte fields at
/// every aligned position of the superblock, cylinder group 0's header, the first inodes and
/// the root directory's first chunk. `cargo test` runs an evenly spread sample; the full run
/// is `cargo test --release -p nixcavate-fs --test ufs -- --ignored`.
fn boundary_values(name: &str, sample: Option<usize>) {
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
    let d = image(name);
    let lay = Layout::of(&d);
    let mut ranges =
        vec![lay.sb..lay.sb + 1376, lay.cg(0)..lay.cg(0) + 168, lay.root_block(&d)..lay.root_block(&d) + 512];
    for ino in 0..24 {
        ranges.push(lay.inode(ino)..lay.inode(ino) + lay.isz);
    }
    let mut cases = Vec::new();
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
    let step = sample.map_or(1, |n| cases.len().div_ceil(n));
    let picked: Vec<(usize, Vec<u8>)> = cases.into_iter().step_by(step).collect();
    run_cases(name, &d, &picked);
}

#[test]
fn boundary_values_sample() {
    boundary_values("ufs2", Some(1500));
    boundary_values("ufs1", Some(1000));
}

#[test]
#[ignore]
fn boundary_values_exhaustive() {
    for name in ["ufs2", "ufs2-4k", "ufs1", "ufs2-suj", "mk2-le", "sol-ufs"] {
        boundary_values(name, None);
    }
}

/// Walk and read speed on a large image: `NIXCAVATE_UFS_BENCH=/path/fs.img cargo test --release
/// -p nixcavate-fs --test ufs -- --ignored walk_speed --nocapture` (a bare UFS image).
#[test]
#[ignore]
fn walk_speed() {
    use std::os::unix::fs::FileExt;
    struct File(std::fs::File, u64);
    impl ReadAt for File {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(buf, offset)
        }
        fn size(&self) -> u64 {
            self.1
        }
    }
    let path = std::env::var("NIXCAVATE_UFS_BENCH").expect("NIXCAVATE_UFS_BENCH");
    let file = std::fs::File::open(path).unwrap();
    let size = file.metadata().unwrap().len();
    let image = File(file, size);
    let start = Instant::now();
    let volume = Ufs::open(&image).unwrap();
    let (mut nodes, mut warnings) = (Vec::new(), 0);
    volume.walk(&mut |n| nodes.push(n), &mut |_| warnings += 1).unwrap();
    let walked = start.elapsed();
    let start = Instant::now();
    let mut bytes = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    for n in nodes.iter().filter(|n| n.kind == Kind::File) {
        let mut at = 0;
        while at < n.size {
            let Ok(k) = volume.read(n.inode, at, &mut buf) else { break };
            if k == 0 {
                break;
            }
            at += k as u64;
            bytes += k as u64;
        }
    }
    let read = start.elapsed();
    println!(
        "{} nodes in {walked:?} ({warnings} warnings); {bytes} bytes read in {read:?} ({:.0} MB/s)",
        nodes.len(),
        bytes as f64 / 1e6 / read.as_secs_f64()
    );
}

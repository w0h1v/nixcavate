//! Regressions from the adversarial review of the disk-image readers: small crafted images
//! (built here by patching the real fixtures) that made a walk or a read do unbounded work,
//! emit unbounded output, or report a path the filesystem does not have.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nixcavate_fs::apfs::Apfs;
use nixcavate_fs::ext4::Ext4;
use nixcavate_fs::xfs::Xfs;
use nixcavate_fs::{Bytes, Kind, Node, ReadAt, Volume};

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs").join(rel);
    zstd::decode_all(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))[..]).unwrap()
}

fn walk(volume: &dyn Volume) -> (Vec<Node>, Vec<String>) {
    let (mut nodes, mut warnings) = (Vec::new(), Vec::new());
    let _ = volume.walk(&mut |n| nodes.push(n), &mut |w| warnings.push(w));
    (nodes, warnings)
}

fn get16(d: &[u8], at: usize) -> usize {
    u16::from_le_bytes(d[at..at + 2].try_into().unwrap()) as usize
}

fn get32(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
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

/// Counts reads and fails every read after `limit`, so a runaway walk ends quickly.
struct Counting<'a> {
    inner: Bytes<'a>,
    reads: AtomicU64,
    limit: u64,
}

impl<'a> Counting<'a> {
    fn new(data: &'a [u8], limit: u64) -> Self {
        Counting { inner: Bytes(data), reads: AtomicU64::new(0), limit }
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl ReadAt for Counting<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if self.reads.fetch_add(1, Ordering::Relaxed) >= self.limit {
            return Err(io::Error::other("read limit of the test reached"));
        }
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

// ---------------------------------------------------------------------------------------
// ext4: the fixture `ext4.img` has 4 KiB blocks, one group, 256-byte inodes, 6000 inodes.

struct Ext4Layout {
    bs: usize,
    isz: usize,
    table: usize,
}

impl Ext4Layout {
    fn of(d: &[u8]) -> Self {
        let bs = 1024 << get32(d, 1024 + 0x18);
        let gdt = if bs == 1024 { 2048 } else { bs };
        Ext4Layout { bs, isz: get16(d, 1024 + 0x58), table: get32(d, gdt + 8) * bs }
    }

    fn inode(&self, n: usize) -> usize {
        self.table + (n - 1) * self.isz
    }

    /// The first block of the root directory (an extent-mapped directory).
    fn root_block(&self, d: &[u8]) -> usize {
        get32(d, self.inode(2) + 0x28 + 12 + 8) * self.bs
    }
}

/// Offset of the root-directory entry whose name satisfies `pred`.
fn ext4_entry(d: &[u8], lay: &Ext4Layout, pred: impl Fn(&[u8]) -> bool) -> usize {
    let block = lay.root_block(d);
    let mut off = 0;
    while off < lay.bs {
        let rec_len = get16(d, block + off + 4);
        let name_len = d[block + off + 6] as usize;
        if pred(&d[block + off + 8..block + off + 8 + name_len]) {
            return block + off;
        }
        off += rec_len;
    }
    panic!("no such root entry");
}

/// Builds a directory inode whose block map names the same three blocks over and over:
/// `nblk` blocks of directory, every one of them the block holding 341 entries `x`.
fn ext4_shared_blocks(d: &mut [u8], lay: &Ext4Layout, ino: usize, nblk: u32) {
    let bs = lay.bs;
    let zero: Vec<usize> =
        (500..d.len() / bs).filter(|&i| d[i * bs..(i + 1) * bs].iter().all(|&b| b == 0)).take(3).collect();
    let (z1, z2, z3) = (zero[0], zero[1], zero[2]);
    let mut off = 0;
    for i in 0..341 {
        let rec_len = if i < 340 { 12 } else { bs - off };
        let at = z3 * bs + off;
        put32(d, at, 19);
        put16(d, at + 4, rec_len as u16);
        d[at + 6] = 1;
        d[at + 7] = 1;
        d[at + 8] = b'x';
        off += rec_len;
    }
    for i in 0..bs / 4 {
        put32(d, z1 * bs + 4 * i, z3 as u32);
        put32(d, z2 * bs + 4 * i, z1 as u32);
    }
    let at = lay.inode(ino);
    d[at..at + lay.isz].fill(0);
    put16(d, at, 0o40755);
    put32(d, at + 4, nblk * bs as u32);
    put16(d, at + 0x1a, 2);
    for i in 0..12 {
        put32(d, at + 0x28 + 4 * i, z3 as u32);
    }
    put32(d, at + 0x28 + 48, z1 as u32);
    put32(d, at + 0x28 + 52, z2 as u32);
    put16(d, at + 0x80, 32);
}

fn ext4_point_a_at(d: &mut [u8], lay: &Ext4Layout, ino: u32) {
    let entry = ext4_entry(d, lay, |n| n == b"a");
    put32(d, entry, ino);
}

#[test]
fn ext4_a_directory_block_is_read_once() {
    let mut d = fixture("ext4/ext4.img.zst");
    let lay = Ext4Layout::of(&d);
    let clean = walk(&Ext4::open(&Bytes(&d)).unwrap()).0.len();
    ext4_shared_blocks(&mut d, &lay, 4000, 2048);
    ext4_point_a_at(&mut d, &lay, 4000);
    let (nodes, warnings) = walk(&Ext4::open(&Bytes(&d)).unwrap());
    assert!(nodes.len() <= clean, "{} nodes from an 8 MiB directory of one shared block", nodes.len());
    let paths: HashSet<&str> = nodes.iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths.len(), nodes.len(), "a path listed twice");
    assert!(!warnings.is_empty());
}

#[test]
fn ext4_paths_are_bounded() {
    // A chain of 1022 inline directories with 48-byte names: 50 KB paths before the fix.
    let mut d = fixture("ext4/ext4.img.zst");
    let lay = Ext4Layout::of(&d);
    let (first, depth) = (4000usize, 1022usize);
    for k in 0..depth {
        let (n, child) = (first + k, first + k + 1);
        let name = format!("{k:04}{}", "D".repeat(44));
        let at = lay.inode(n);
        d[at..at + lay.isz].fill(0);
        put16(&mut d, at, 0o40755);
        put32(&mut d, at + 4, 60);
        put16(&mut d, at + 0x1a, 2);
        put32(&mut d, at + 0x20, 0x1000_0000);
        let ib = at + 0x28;
        put32(&mut d, ib, n as u32);
        put32(&mut d, ib + 4, child as u32);
        put16(&mut d, ib + 8, 56);
        d[ib + 10] = name.len() as u8;
        d[ib + 11] = 2;
        d[ib + 12..ib + 12 + name.len()].copy_from_slice(name.as_bytes());
    }
    ext4_shared_blocks(&mut d, &lay, first + depth, 4);
    ext4_point_a_at(&mut d, &lay, first as u32);
    let (nodes, warnings) = walk(&Ext4::open(&Bytes(&d)).unwrap());
    let longest = nodes.iter().map(|n| n.path.len()).max().unwrap();
    let total: usize = nodes.iter().map(|n| n.path.len()).sum();
    assert!(longest <= 4096, "a path of {longest} bytes");
    assert!(total < 1 << 20, "{total} path bytes");
    assert!(!warnings.is_empty());
}

#[test]
fn ext4_entry_names_are_validated() {
    let mut d = fixture("ext4/ext4.img.zst");
    let lay = Ext4Layout::of(&d);
    let clean = walk(&Ext4::open(&Bytes(&d)).unwrap()).0;
    let deep = clean.iter().find(|n| n.path == "a/b/c/d/e/deep.txt").unwrap().inode;
    // A name with slashes that shadows a real path, a name with a NUL, an empty name, and a
    // non-UTF-8 name that reads the same as an existing one once converted.
    let long = ext4_entry(&d, &lay, |n| n.len() == 255);
    let shadow = b"a/b/c/d/e/deep.txt";
    put32(&mut d, long, 19);
    d[long + 6] = shadow.len() as u8;
    d[long + 8..long + 8 + shadow.len()].copy_from_slice(shadow);
    let future = ext4_entry(&d, &lay, |n| n == b"future");
    d[future + 8 + 2] = 0;
    let past = ext4_entry(&d, &lay, |n| n == b"past");
    d[past + 6] = 0;
    let medium = ext4_entry(&d, &lay, |n| n == b"medium.txt");
    d[medium + 6] = 8;
    d[medium + 8..medium + 16].copy_from_slice(b"bad\xfename");

    let (nodes, warnings) = walk(&Ext4::open(&Bytes(&d)).unwrap());
    let shadows: Vec<u64> = nodes.iter().filter(|n| n.path == "a/b/c/d/e/deep.txt").map(|n| n.inode).collect();
    assert_eq!(shadows, [deep], "only the real file has that path");
    assert!(nodes.iter().all(|n| !n.path.is_empty() && !n.path.contains('\0')));
    assert_eq!(nodes.iter().filter(|n| n.path == "bad\u{fffd}name").count(), 1);
    let paths: HashSet<&str> = nodes.iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths.len(), nodes.len(), "a path listed twice");
    assert!(warnings.len() >= 2, "{warnings:?}");
}

#[test]
fn ext4_concurrent_reads_match_sequential_reads() {
    // Reads share the inode-table cache; many threads must see what one thread sees.
    let d = fixture("ext4/ext4-metabg.img.zst");
    let image = Bytes(&d);
    let volume = Ext4::open(&image).unwrap();
    let files: Vec<Node> = walk(&volume).0.into_iter().filter(|n| n.kind == Kind::File && n.size < 1 << 20).collect();
    let expected: Vec<Vec<u8>> =
        files.iter().map(|n| nixcavate_fs::read_all(&volume, n.inode, n.size, 1 << 20).unwrap()).collect();
    std::thread::scope(|scope| {
        for t in 0..8 {
            let (volume, files, expected) = (&volume, &files, &expected);
            scope.spawn(move || {
                for i in (0..files.len()).map(|i| (i * 7 + t * 131) % files.len()) {
                    let got = nixcavate_fs::read_all(volume, files[i].inode, files[i].size, 1 << 20).unwrap();
                    assert!(got == expected[i], "{}", files[i].path);
                }
            });
        }
    });
}

/// An image that reads as zeros past its real data, as an E01 of mostly empty chunks does.
struct Padded {
    data: Vec<u8>,
    size: u64,
}

impl ReadAt for Padded {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.size) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"));
        }
        buf.fill(0);
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[test]
fn ext4_group_count_must_agree_with_the_block_count() {
    let mut data = fixture("ext4/ext4.img.zst");
    put32(&mut data, 1024, u32::MAX); // s_inodes_count: 715,828 groups of 6000 inodes
    let image = Padded { data, size: 1 << 40 };
    assert!(Ext4::open(&image).is_err(), "inode and block counts disagree on the number of groups");
}

#[test]
fn ext4_size_high_bits_apply_to_files_and_directories_only() {
    let mut d = fixture("ext4/ext4.img.zst");
    let lay = Ext4Layout::of(&d);
    let clean = walk(&Ext4::open(&Bytes(&d)).unwrap()).0;
    let pick = |p: &str| clean.iter().find(|n| n.path == p).unwrap().clone();
    let (link, fifo) = (pick("link_short"), pick("fifo"));
    for node in [&link, &fifo] {
        put32(&mut d, lay.inode(node.inode as usize) + 0x6c, 1);
    }
    let (nodes, warnings) = walk(&Ext4::open(&Bytes(&d)).unwrap());
    assert!(warnings.is_empty(), "{warnings:?}");
    let got = |p: &str| nodes.iter().find(|n| n.path == p).unwrap().clone();
    assert_eq!((got("link_short").size, got("link_short").link_target), (link.size, link.link_target));
    assert_eq!(got("fifo").size, fifo.size);
}

// ---------------------------------------------------------------------------------------
// XFS: inode 172 of v5.img is the symlink `link_long`.

fn be16(d: &[u8], at: usize) -> u64 {
    u64::from(u16::from_be_bytes(d[at..at + 2].try_into().unwrap()))
}

fn be32(d: &[u8], at: usize) -> u64 {
    u64::from(u32::from_be_bytes(d[at..at + 4].try_into().unwrap()))
}

/// Turns the symlink into a B+tree fork whose root names one interior block 20 times, whose
/// 251 pointers all name one leaf of 251 extents. With `fan`, every directory entry in the
/// data blocks (but those of `big` and `dir_leaf`) is pointed at the symlink.
fn xfs_bmbt(fan: bool) -> Vec<u8> {
    let mut d = fixture("xfs/v5.img.zst");
    let bs = be32(&d, 4) as usize;
    let (blog, ilog, inopb, agblog) = (u64::from(d[120]), u64::from(d[122]), u64::from(d[123]), u64::from(d[124]));
    let agblocks = be32(&d, 84);
    let isz = 1usize << ilog;
    const S: u64 = 172;
    let agbn = (S >> inopb) & ((1 << agblog) - 1);
    let agno = S >> (inopb + agblog);
    let p = (((agno * agblocks + agbn) << blog) + ((S & ((1 << inopb) - 1)) << ilog)) as usize;
    assert_eq!(&d[p..p + 2], b"IN");
    let free: Vec<u64> = (agblocks + 100..agblocks + 20000)
        .filter(|&b| d[b as usize * bs..(b as usize + 1) * bs].iter().all(|&x| x == 0))
        .take(2)
        .collect();
    let (a, b) = (free[0], free[1]);
    let fsb = |blk: u64| (1u64 << agblog) | (blk - agblocks);
    let block = |level: u16, n: u16| {
        let mut x = vec![0u8; bs];
        x[0..4].copy_from_slice(b"BMA3");
        x[4..6].copy_from_slice(&level.to_be_bytes());
        x[6..8].copy_from_slice(&n.to_be_bytes());
        x
    };
    let mut leaf = block(0, 251);
    for i in 0..251u64 {
        let (start, count) = (fsb(b), 1u64);
        let l0 = (i << 9) | (start >> 43);
        let l1 = ((start & ((1 << 43) - 1)) << 21) | count;
        leaf[72 + 16 * i as usize..80 + 16 * i as usize].copy_from_slice(&l0.to_be_bytes());
        leaf[80 + 16 * i as usize..88 + 16 * i as usize].copy_from_slice(&l1.to_be_bytes());
    }
    let mut mid = block(1, 251);
    for i in 0..251usize {
        mid[72 + 8 * i..80 + 8 * i].copy_from_slice(&(i as u64 * 251).to_be_bytes());
        mid[72 + 251 * 8 + 8 * i..80 + 251 * 8 + 8 * i].copy_from_slice(&fsb(b).to_be_bytes());
    }
    d[a as usize * bs..(a as usize + 1) * bs].copy_from_slice(&mid);
    d[b as usize * bs..(b as usize + 1) * bs].copy_from_slice(&leaf);
    d[p + 5] = 3; // btree format
    d[p + 82] = 0; // no attribute fork
    let fork = p + 176;
    let maxrecs = (isz - 176 - 4) / 16;
    d[fork..fork + 2].copy_from_slice(&2u16.to_be_bytes());
    d[fork + 2..fork + 4].copy_from_slice(&(maxrecs as u16).to_be_bytes());
    for i in 0..maxrecs {
        d[fork + 4 + 8 * i..fork + 12 + 8 * i].copy_from_slice(&(i as u64 * 63001).to_be_bytes());
        let at = fork + 4 + maxrecs * 8 + 8 * i;
        d[at..at + 8].copy_from_slice(&fsb(a).to_be_bytes());
    }
    d[p + 76..p + 80].fill(0); // di_nextents
    if fan {
        let mut redirected = 0;
        for blk in 0..d.len() / bs {
            let o = blk * bs;
            let magic = &d[o..o + 4];
            if magic != b"XDB3" && magic != b"XDD3" {
                continue;
            }
            let mut end = o + bs;
            if magic == b"XDB3" {
                end = end - 8 - 8 * be32(&d, end - 8) as usize;
            }
            let mut q = o + 64;
            while q < end {
                if be16(&d, q) == 0xffff {
                    q += be16(&d, q + 2) as usize;
                    continue;
                }
                let nl = d[q + 8] as usize;
                let name = &d[q + 9..q + 9 + nl];
                if ![&b"."[..], b"..", b"big", b"dir_leaf"].contains(&name) {
                    d[q..q + 8].copy_from_slice(&S.to_be_bytes());
                    redirected += 1;
                }
                q += (8 + 1 + nl + 1 + 2 + 7) & !7;
            }
        }
        assert!(redirected > 1000, "{redirected}");
    }
    d
}

#[test]
fn xfs_btree_symlink_is_refused_without_walking_the_tree() {
    let d = xfs_bmbt(false);
    let image = Counting::new(&d, 1 << 20);
    let fs = Xfs::open(&image).unwrap();
    let before = image.reads();
    let mut buf = [0u8; 64];
    assert!(fs.read(172, 0, &mut buf).is_err());
    assert!(image.reads() - before < 50, "{} reads for one symlink", image.reads() - before);
}

#[test]
fn xfs_walk_does_not_rebuild_extent_maps_per_entry() {
    let d = xfs_bmbt(true);
    let image = Counting::new(&d, 200_000);
    let fs = Xfs::open(&image).unwrap();
    let (nodes, _) = walk(&fs);
    assert!(image.reads() < 200_000, "{} reads to walk {} nodes", image.reads(), nodes.len());
}

// ---------------------------------------------------------------------------------------
// APFS: the volume "TestVol" of basic.dmg, with its file-system tree replaced by a crafted
// physical B-tree.

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

fn checksum_ok(b: &[u8]) -> bool {
    u64::from_le_bytes(b[..8].try_into().unwrap()) == fletcher64(&b[8..])
}

fn sign(b: &mut [u8]) {
    let sum = fletcher64(&b[8..]);
    b[..8].copy_from_slice(&sum.to_le_bytes());
}

/// The APFS partition of basic.dmg.
fn apfs_basic() -> Vec<u8> {
    let d = fixture("apfs/basic.dmg.zst");
    let entries = u64::from_le_bytes(d[512 + 72..512 + 80].try_into().unwrap()) as usize;
    for i in 0..128 {
        let e = &d[entries * 512 + i * 128..entries * 512 + i * 128 + 128];
        if e[..4] == [0xef, 0x57, 0x34, 0x7c] {
            let first = u64::from_le_bytes(e[32..40].try_into().unwrap()) as usize;
            let last = u64::from_le_bytes(e[40..48].try_into().unwrap()) as usize;
            return d[first * 512..(last + 1) * 512].to_vec();
        }
    }
    panic!("no APFS partition");
}

struct ApfsBuilder {
    part: Vec<u8>,
    free: std::vec::IntoIter<usize>,
}

const BS: usize = 4096;

type Record = (Vec<u8>, Vec<u8>);

impl ApfsBuilder {
    fn new() -> Self {
        let part = apfs_basic();
        let free: Vec<usize> =
            (0..part.len() / BS).filter(|&i| part[i * BS..(i + 1) * BS].iter().all(|&b| b == 0)).collect();
        ApfsBuilder { part, free: free.into_iter() }
    }

    /// Writes a B-tree node of the file-system tree at a free block and returns its address.
    fn node(&mut self, level: u16, entries: &[Record], root: bool) -> u64 {
        let paddr = self.free.next().unwrap();
        let mut b = vec![0u8; BS];
        put64(&mut b, 8, paddr as u64);
        put64(&mut b, 16, 5);
        put32(&mut b, 24, 0x4000_0000 | if root { 2 } else { 3 });
        put32(&mut b, 28, 0xe);
        let n = entries.len();
        let keys = 56 + 8 * n;
        let vend = BS - if root { 40 } else { 0 };
        put16(&mut b, 32, u16::from(root) | if level == 0 { 2 } else { 0 });
        put16(&mut b, 34, level);
        put32(&mut b, 36, n as u32);
        put16(&mut b, 42, (8 * n) as u16);
        let (mut ko, mut vo) = (0, 0);
        for (i, (k, v)) in entries.iter().enumerate() {
            b[keys + ko..keys + ko + k.len()].copy_from_slice(k);
            vo += v.len();
            b[vend - vo..vend - vo + v.len()].copy_from_slice(v);
            for (j, x) in [ko, k.len(), vo, v.len()].into_iter().enumerate() {
                put16(&mut b, 56 + 8 * i + 2 * j, x as u16);
            }
            ko += k.len();
        }
        assert!(keys + ko <= vend - vo, "node overflow");
        sign(&mut b);
        self.part[paddr * BS..(paddr + 1) * BS].copy_from_slice(&b);
        paddr as u64
    }

    /// Points every volume superblock at a physical tree rooted at `root`.
    fn finish(mut self, root: u64) -> Vec<u8> {
        for blk in self.part.chunks_mut(BS) {
            if &blk[32..36] == b"APSB" && checksum_ok(blk) {
                put32(blk, 116, 0x4000_0002);
                put64(blk, 136, root);
                sign(blk);
            }
        }
        self.part
    }
}

fn jkey(oid: u64, ty: u64) -> Vec<u8> {
    (oid | (ty << 60)).to_le_bytes().to_vec()
}

fn drec(parent: u64, name: &[u8], child: u64, dtype: u16) -> Record {
    let mut k = jkey(parent, 9);
    k.extend_from_slice(&(name.len() as u32 + 1).to_le_bytes());
    k.extend_from_slice(name);
    k.push(0);
    let mut v = child.to_le_bytes().to_vec();
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(&dtype.to_le_bytes());
    (k, v)
}

fn inode(oid: u64, parent: u64, mode: u16) -> Record {
    let mut v = vec![0u8; 92];
    put64(&mut v, 0, parent);
    put64(&mut v, 8, oid);
    put32(&mut v, 56, 1);
    put16(&mut v, 80, mode);
    (jkey(oid, 3), v)
}

#[test]
fn apfs_index_entries_that_repeat_a_child_are_not_followed_again() {
    // Root (level 2): 40 pointers to one index node whose 40 pointers name one leaf of 100
    // directory records: 160,000 records for the root directory before the fix.
    const CHILD: u64 = 0x12345;
    let mut b = ApfsBuilder::new();
    let records: Vec<Record> = (0..100).map(|_| drec(2, b"x", CHILD, 8)).collect();
    let leaf = b.node(0, &records, false);
    let inode_leaf = b.node(0, &[inode(CHILD, 2, 0o100644)], false);
    let index = b.node(1, &vec![(jkey(2, 9), leaf.to_le_bytes().to_vec()); 40], false);
    let inode_index = b.node(1, &[(jkey(CHILD, 3), inode_leaf.to_le_bytes().to_vec())], false);
    let mut top = vec![(jkey(2, 9), index.to_le_bytes().to_vec()); 40];
    top.push((jkey(CHILD, 3), inode_index.to_le_bytes().to_vec()));
    let root = b.node(2, &top, true);
    let part = b.finish(root);
    let image = Bytes(&part);
    let volume = Apfs::open(&image).unwrap().volume(0).unwrap();
    let (nodes, warnings) = walk(&volume);
    assert!(nodes.len() < 100, "{} nodes", nodes.len());
    assert!(!warnings.is_empty());
}

#[test]
fn apfs_paths_are_bounded() {
    // 40 nested directories, each with a 255-byte name: 10 KB paths before the fix.
    const BASE: u64 = 0x10000;
    const N: u64 = 40;
    let name = |i: u64| {
        let mut n = format!("{i:06}").into_bytes();
        n.resize(255, b'N');
        n
    };
    let mut records = vec![drec(2, &name(0), BASE, 4)];
    for i in 0..N {
        records.push(inode(BASE + i, if i == 0 { 2 } else { BASE + i - 1 }, 0o40755));
        if i + 1 < N {
            records.push(drec(BASE + i, &name(i + 1), BASE + i + 1, 4));
        }
    }
    let mut b = ApfsBuilder::new();
    let pack = |items: Vec<Record>| {
        let mut groups: Vec<Vec<Record>> = vec![Vec::new()];
        let mut used = 0;
        for e in items {
            let size = 8 + e.0.len() + e.1.len();
            if !groups.last().unwrap().is_empty() && used + size > 4040 {
                groups.push(Vec::new());
                used = 0;
            }
            used += size;
            groups.last_mut().unwrap().push(e);
        }
        groups
    };
    let mut ptrs: Vec<Record> = Vec::new();
    for group in pack(records) {
        let p = b.node(0, &group, false);
        ptrs.push((group[0].0[..8].to_vec(), p.to_le_bytes().to_vec()));
    }
    assert!(ptrs.len() * 24 <= 4000);
    let root = b.node(1, &ptrs, true);
    let part = b.finish(root);
    let image = Bytes(&part);
    let volume = Apfs::open(&image).unwrap().volume(0).unwrap();
    let (nodes, warnings) = walk(&volume);
    assert!(nodes.iter().any(|n| n.kind == Kind::Directory));
    let longest = nodes.iter().map(|n| n.path.len()).max().unwrap();
    assert!(longest <= 4096, "a path of {longest} bytes");
    assert!(!warnings.is_empty());
}

//! Tests of the virtual disk readers against fixtures made by `qemu-img` (see
//! `test_files/image/vdisk/build.sh`): every variant must read back byte for byte as the raw
//! disk it was converted from, and damaged or hostile files must be refused without a panic.

use super::*;
use crate::image::{qcow2, vdi, vhd, vhdx, vmdk};
use nixcavate_fs::ReadAt;
use std::io::Read;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/vdisk")
}

fn unzst(name: &str) -> Vec<u8> {
    let path = fixtures().join(format!("{name}.zst"));
    zstd::decode_all(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))[..]).unwrap()
}

fn raw() -> Vec<u8> {
    zstd::decode_all(&std::fs::read(fixtures().join("disk.img.zst")).unwrap()[..]).unwrap()
}

/// A scratch directory, removed afterwards.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("nixcavate-vdisk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn put(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    /// The fixture `name` (stored as `name.zst`) written here under `name`.
    fn stage(&self, name: &str) -> PathBuf {
        self.put(name, &unzst(name))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open_path(path: &Path) -> io::Result<Disk> {
    let mut head = [0u8; 512];
    let n = std::fs::File::open(path)?.read(&mut head)?;
    open(path, &head[..n])?.ok_or_else(|| io::Error::other("not recognised as a virtual disk"))
}

/// A tiny deterministic generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// The whole disk through `read_at` in 1 MiB steps, then random reads that straddle clusters,
/// all equal to `raw`; the disk may be longer than `raw` only by zeros.
fn assert_same(what: &str, reader: &dyn ReadAt, raw: &[u8]) {
    let size = reader.size();
    assert!(size >= raw.len() as u64, "{what}: size {size} is smaller than the raw disk");
    let mut at = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while at < size {
        let n = buf.len().min((size - at) as usize);
        reader.read_at(at, &mut buf[..n]).unwrap_or_else(|e| panic!("{what}: read at {at}: {e}"));
        let want = raw.get(at as usize..(at as usize + n).min(raw.len())).unwrap_or_default();
        assert!(buf[..want.len()] == *want, "{what}: bytes differ in the MiB at {at}");
        assert!(buf[want.len()..n].iter().all(|&b| b == 0), "{what}: bytes past the raw disk are not zero");
        at += n as u64;
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..400 {
        let len = 1 + rng.below(70_000) as usize;
        let from = rng.below((raw.len() - len) as u64) as usize;
        let mut out = vec![0u8; len];
        reader.read_at(from as u64, &mut out).unwrap_or_else(|e| panic!("{what}: read {len} at {from}: {e}"));
        assert!(out == raw[from..from + len], "{what}: random read of {len} at {from} differs");
    }
    // The ends of the disk.
    assert!(reader.read_at(size, &mut [0u8; 1]).is_err(), "{what}: a read past the end succeeded");
    assert!(reader.read_at(size - 1, &mut [0u8; 1]).is_ok(), "{what}: the last byte");
    let mut empty = [];
    assert!(reader.read_at(size, &mut empty).is_ok());
}

#[test]
fn crc32c_known_answer() {
    // The RFC 3720 check values.
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
}

#[test]
fn blocks_split_reads_and_refuse_the_end() {
    let mut seen = Vec::new();
    let mut buf = [0u8; 7];
    for_blocks(20, 4, 3, &mut buf, |start, within, part| {
        seen.push((start, within, part.len()));
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, [(0, 3, 1), (4, 0, 4), (8, 0, 2)]);
    assert!(for_blocks(20, 4, 14, &mut buf, |_, _, _| Ok(())).is_err());
    assert!(for_blocks(20, 4, u64::MAX, &mut buf, |_, _, _| Ok(())).is_err());
    assert!(for_blocks(20, 4, 20, &mut [], |_, _, _| Ok(())).is_ok());
}

fn check(name: &str, note: &str) -> Disk {
    let dir = Dir::new(&name.replace('.', "-"));
    let path = dir.stage(name);
    let disk = open_path(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(disk.notes[0].contains(note), "{name}: {:?}", disk.notes);
    assert_same(name, &*disk.reader, &raw());
    disk
}

#[test]
fn qcow2_variants_read_back_as_the_raw_disk() {
    for (name, note) in [
        ("qcow2-v3.qcow2", "qcow2 version 3"),
        ("qcow2-v2.qcow2", "qcow2 version 2"),
        ("qcow2-compressed.qcow2", "64 KiB clusters"),
        ("qcow2-compressed-4k.qcow2", "4 KiB clusters"),
        ("qcow2-zstd.qcow2", "zstd compression"),
        ("qcow2-512.qcow2", "512 byte clusters"),
        ("qcow2-2m.qcow2", "2048 KiB clusters"),
        ("qcow2-2m-compressed.qcow2", "2048 KiB clusters"),
        ("qcow2-extl2.qcow2", "extended L2"),
        ("qcow2-extl2-compressed.qcow2", "extended L2"),
    ] {
        let disk = check(name, note);
        assert_eq!(disk.notes.len(), 1, "{name}: {:?}", disk.notes);
        assert_eq!(disk.reader.size(), 8 << 20, "{name}");
    }
}

#[test]
fn vmdk_variants_read_back_as_the_raw_disk() {
    for name in ["vmdk-monolithicSparse.vmdk", "vmdk-streamOptimized.vmdk"] {
        let disk = check(name, "sparse extent file");
        assert_eq!(disk.reader.size(), 8 << 20, "{name}");
    }
    // Descriptor files; the extents are staged next to them (flat extents are the raw disk).
    let raw = raw();
    let dir = Dir::new("vmdk-desc");
    dir.stage("vmdk-twoGbMaxExtentSparse-s001.vmdk");
    let sparse = dir.stage("vmdk-twoGbMaxExtentSparse.vmdk");
    let disk = open_path(&sparse).unwrap();
    assert!(disk.notes[0].contains("(descriptor)"), "{:?}", disk.notes);
    assert_same("twoGbMaxExtentSparse", &*disk.reader, &raw);
    for name in ["vmdk-monolithicFlat.vmdk", "vmdk-twoGbMaxExtentFlat.vmdk"] {
        let path = dir.stage(name);
        // The descriptor says which file holds the data.
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        let extent = text.lines().find(|l| l.starts_with("RW ")).unwrap().split('"').nth(1).unwrap().to_string();
        let flat = dir.put(&extent, &raw);
        let disk = open_path(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(disk.notes.len(), 1, "{:?}", disk.notes);
        assert_same(name, &*disk.reader, &raw);
        std::fs::remove_file(flat).unwrap();
        // Without the extent: one warning, and a read there fails.
        let disk = open_path(&path).unwrap();
        assert_eq!(disk.notes.len(), 2, "{:?}", disk.notes);
        assert!(disk.notes[1].contains("is missing"), "{:?}", disk.notes);
        assert!(disk.reader.read_at(0, &mut [0u8; 16]).is_err());
    }
}

/// Several extents of both kinds, end to end, with a case-different file name.
#[test]
fn a_descriptor_with_several_extents_is_one_disk() {
    let raw = raw();
    let dir = Dir::new("vmdk-multi");
    let third = raw.len() / 3 / 512 * 512;
    dir.put("part-flat-1.vmdk", &raw[..third]);
    dir.put("PART-FLAT-2.VMDK", &raw[third..2 * third]);
    dir.put("part-flat-3.vmdk", &raw[2 * third..]);
    let sectors = |n: usize| n / 512;
    let descriptor = format!(
        "# Disk DescriptorFile\nversion=1\nCID=1\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n\
         RW {} FLAT \"part-flat-1.vmdk\" 0\nRW {} FLAT \"sub/dir/part-flat-2.vmdk\" 0\nRW {} VMFS \"part-flat-3.vmdk\" 0\n",
        sectors(third),
        sectors(third),
        sectors(raw.len() - 2 * third)
    );
    let path = dir.put("multi.vmdk", descriptor.as_bytes());
    let disk = open_path(&path).unwrap();
    assert!(disk.notes[0].contains("3 extent(s)"), "{:?}", disk.notes);
    assert_eq!(disk.notes.len(), 1, "{:?}", disk.notes);
    assert_same("multi", &*disk.reader, &raw);
}

#[test]
fn vmdk_extent_names_are_confined_to_the_descriptor_directory() {
    let dir = Dir::new("vmdk-names");
    for name in ["/etc/passwd", "../up.vmdk", "sub/../../up.vmdk", "C:\\disks\\x.vmdk", "\\\\host\\share\\x.vmdk"] {
        let descriptor = format!("# Disk DescriptorFile\nparentCID=ffffffff\nRW 16 FLAT \"{name}\" 0\n");
        let err = open_path(&dir.put("d.vmdk", descriptor.as_bytes())).err().unwrap().to_string();
        assert!(err.contains("not followed"), "{name}: {err}");
    }
    // A symbolic link is never followed.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/hosts", dir.0.join("link.vmdk")).unwrap();
        let descriptor = "# Disk DescriptorFile\nparentCID=ffffffff\nRW 8 FLAT \"link.vmdk\" 0\n";
        let disk = open_path(&dir.put("d.vmdk", descriptor.as_bytes())).unwrap();
        assert!(disk.notes[1].contains("link.vmdk is missing"), "{:?}", disk.notes);
    }
}

#[test]
fn vhd_variants_read_back_as_the_raw_disk() {
    let disk = check("vpc-dynamic.vhd", "VHD dynamic");
    assert_eq!(disk.reader.size(), 8 << 20);
    let disk = check("vpc-fixed.vhd", "VHD fixed");
    // The 512-byte footer at the end of the file is not part of the disk.
    assert_eq!(disk.reader.size(), 8 << 20);
    assert!(disk.notes[0].contains("footer"), "{:?}", disk.notes);
    // Without force_size qemu rounds the disk to its CHS geometry: still the raw disk, then zeros.
    let disk = check("vpc-chs.vhd", "VHD dynamic");
    assert!(disk.reader.size() >= 6 << 20);
}

#[test]
fn vhdx_variants_read_back_as_the_raw_disk() {
    for name in ["vhdx-dynamic.vhdx", "vhdx-1m.vhdx", "vhdx-fixed.vhdx"] {
        let disk = check(name, "VHDX virtual disk");
        assert_eq!(disk.notes.len(), 1, "{name}: {:?}", disk.notes);
        assert_eq!(disk.reader.size(), 8 << 20, "{name}");
    }
}

#[test]
fn a_vhdx_that_was_killed_mid_write_warns_about_its_log() {
    let dir = Dir::new("vhdx-dirty");
    let disk = open_path(&dir.stage("vhdx-dirty.vhdx")).unwrap();
    assert_eq!(disk.notes.len(), 2, "{:?}", disk.notes);
    assert!(disk.notes[1].contains("not closed cleanly") && disk.notes[1].contains("not replayed"), "{:?}", disk.notes);
    // It still reads, without the log.
    assert!(disk.reader.read_at(0, &mut [0u8; 4096]).is_ok());
}

#[test]
fn vdi_variants_read_back_as_the_raw_disk() {
    let disk = check("vdi-dynamic.vdi", "VDI dynamic");
    assert_eq!(disk.reader.size(), 8 << 20);
    let disk = check("vdi-static.vdi", "VDI fixed");
    assert_eq!(disk.reader.size(), 8 << 20);
}

fn be32(v: &mut [u8], at: usize, value: u32) {
    v[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn be64(v: &mut [u8], at: usize, value: u64) {
    v[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn le32(v: &mut [u8], at: usize, value: u32) {
    v[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn le64(v: &mut [u8], at: usize, value: u64) {
    v[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn rd64(v: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(v[at..at + 8].try_into().unwrap())
}

fn error_of(name: &str, data: Vec<u8>) -> String {
    let dir = Dir::new(&format!("err-{}", name.replace('.', "-")));
    open_path(&dir.put(name, &data)).err().unwrap_or_else(|| panic!("{name}: opened")).to_string()
}

/// A VHD footer or dynamic header checksum is the one's complement of the byte sum.
fn vhd_sum(data: &mut [u8], field: usize) {
    data[field..field + 4].fill(0);
    let sum = data.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
    data[field..field + 4].copy_from_slice(&(!sum).to_be_bytes());
}

fn vhdx_crc(data: &mut [u8]) {
    data[4..8].fill(0);
    let crc = crc32c(data);
    data[4..8].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn unreadable_variants_are_refused_with_the_reason() {
    assert!(error_of("a.qcow2", unzst("qcow2-backing.qcow2")).contains("backing file (base.raw)"));
    assert!(error_of("a.qcow2", unzst("qcow2-luks.qcow2")).contains("encrypted (LUKS encryption)"));
    assert!(error_of("a.qcow2", unzst("qcow2-external.qcow2")).contains("external data file"));
    assert!(error_of("a.vmdk", unzst("vmdk-child.vmdk")).contains("has a parent (base.vmdk)"));

    // A qcow2 with an unknown incompatible feature, a bad version.
    let mut q = unzst("qcow2-v3.qcow2");
    q[79] |= 0x80;
    assert!(error_of("a.qcow2", q).contains("unknown incompatible feature"));
    let mut q = unzst("qcow2-v3.qcow2");
    be32(&mut q, 4, 4);
    assert!(error_of("a.qcow2", q).contains("version 4 is not supported"));
    let mut q = unzst("qcow2-v3.qcow2");
    be32(&mut q, 4, 1);
    assert!(error_of("a.qcow2", q).contains("old qcow format"));

    // A dynamic VHD turned into a differencing one, with a parent name.
    let mut v = unzst("vpc-dynamic.vhd");
    be32(&mut v, 60, 4);
    vhd_sum(&mut v[..512], 64);
    let at = rd64(&v, 16) as usize;
    for (i, c) in "parent.vhd".encode_utf16().enumerate() {
        v[at + 64 + 2 * i..at + 66 + 2 * i].copy_from_slice(&c.to_be_bytes());
    }
    vhd_sum(&mut v[at..at + 1024], 36);
    let err = error_of("a.vhd", v);
    assert!(err.contains("differencing disk with parent parent.vhd"), "{err}");

    // A VHDX that says it has a parent (file parameters flag, not covered by a checksum).
    let mut x = unzst("vhdx-dynamic.vhdx");
    let params = [0x37u8, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
    let meta = (1..64).map(|m| m << 20).find(|&o| x[o..].starts_with(b"metadata")).unwrap();
    let entry = (0..20).map(|i| meta + 32 + 32 * i).find(|&e| x[e..e + 16] == params).unwrap();
    let at = meta + u32::from_le_bytes(x[entry + 16..entry + 20].try_into().unwrap()) as usize;
    le32(&mut x, at + 4, 2);
    let err = error_of("a.vhdx", x);
    assert!(err.contains("differencing disk"), "{err}");

    // VDI snapshots and differencing images.
    let mut d = unzst("vdi-dynamic.vdi");
    le32(&mut d, 76, 4);
    assert!(error_of("a.vdi", d).contains("differencing"));
    let mut d = unzst("vdi-dynamic.vdi");
    le32(&mut d, 68, 0x0001_0000);
    assert!(error_of("a.vdi", d).contains("version 1.0"));

    // ESXi snapshot deltas, by their extent type and by their file signature.
    let desc = "# Disk DescriptorFile\nparentCID=ffffffff\nRW 16 VMFSSPARSE \"x-delta.vmdk\"\n";
    assert!(error_of("a.vmdk", desc.as_bytes().to_vec()).contains("ESXi snapshot delta"));
    let desc = "# Disk DescriptorFile\nparentCID=ffffffff\nRW 16 SESPARSE \"x-sesparse.vmdk\"\n";
    assert!(error_of("a.vmdk", desc.as_bytes().to_vec()).contains("ESXi snapshot delta"));
    assert!(error_of("a.vmdk", b"COWD\x01\0\0\0".to_vec()).contains("consolidate the snapshots"));
    let desc = "# Disk DescriptorFile\nparentCID=1234abcd\nparentFileNameHint=\"base.vmdk\"\nRW 16 FLAT \"x\" 0\n";
    assert!(error_of("a.vmdk", desc.as_bytes().to_vec()).contains("has a parent (base.vmdk)"));
}

#[test]
fn a_dirty_or_corrupt_qcow2_warns_and_is_read() {
    let raw = raw();
    for (bit, text) in [(1u8, "not closed cleanly"), (2, "marked corrupt")] {
        let mut q = unzst("qcow2-v3.qcow2");
        q[79] |= bit;
        let disk = qcow2::open(Box::new(q)).unwrap();
        assert_eq!(disk.notes.len(), 2, "{:?}", disk.notes);
        assert!(disk.notes[1].contains(text), "{:?}", disk.notes);
        assert_same("dirty", &*disk.reader, &raw);
    }
}

/// A raw-deflate stream (or zstd frame) of `n` zero bytes: tiny, and inflates far beyond a cluster.
fn bomb(zstd: bool, n: usize) -> Vec<u8> {
    use std::io::Write;
    let zeros = vec![0u8; n];
    if zstd {
        zstd::encode_all(&zeros[..], 19).unwrap()
    } else {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&zeros).unwrap();
        e.finish().unwrap()
    }
}

fn qcow2_l2_entry_slot(q: &[u8], cluster_index: u64) -> usize {
    let cluster = 1u64 << u32::from_be_bytes(q[20..24].try_into().unwrap());
    let l1 = rd64(q, 40) as usize;
    let l2_entries = cluster / 8;
    let l2 = (rd64(q, l1 + (cluster_index / l2_entries) as usize * 8) & 0x00ff_ffff_ffff_fe00) as usize;
    assert_ne!(l2, 0);
    l2 + (cluster_index % l2_entries) as usize * 8
}

#[test]
fn hostile_qcow2_headers_and_tables_are_errors() {
    let good = unzst("qcow2-v3.qcow2");
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut q = good.clone();
        f(&mut q);
        q
    };
    for bits in [0u32, 8, 22, 31, u32::MAX] {
        let err = error_of("a.qcow2", patched(&|q| be32(q, 20, bits)));
        assert!(err.contains("cluster_bits"), "{bits}: {err}");
    }
    assert!(error_of("a.qcow2", patched(&|q| be32(q, 36, u32::MAX))).contains("L1 table"));
    assert!(error_of("a.qcow2", patched(&|q| be32(q, 36, 0))).contains("L1 table"));
    assert!(error_of("a.qcow2", patched(&|q| be64(q, 24, 1 << 62))).contains("L1 table"));
    assert!(error_of("a.qcow2", patched(&|q| be64(q, 24, u64::MAX))).contains("implausible virtual size"));
    assert!(error_of("a.qcow2", patched(&|q| be64(q, 40, u64::MAX - 3))).contains("outside the file"));
    assert!(error_of("a.qcow2", patched(&|q| q.truncate(60))).contains("too short"));
    assert!(error_of("a.qcow2", patched(&|q| be32(q, 100, 8))).contains("header length"));

    // Entries that point outside the file or at themselves are errors or plain data, never a panic.
    let l1 = rd64(&good, 40) as usize;
    for target in [1u64 << 50, !0x1ffu64, (good.len() as u64 + 65536) & !0xffff, 0x200, l1 as u64] {
        let q = patched(&|q| be64(q, l1, target));
        let disk = qcow2::open(Box::new(q)).unwrap();
        let mut buf = vec![0u8; 8 << 20];
        let _ = disk.reader.read_at(0, &mut buf);
    }
    let slot = qcow2_l2_entry_slot(&good, 0);
    for entry in [1u64 << 50, 0x00ff_ffff_ffff_fe00, 0x200, slot as u64 & !0xffff, (1 << 62) | (1 << 40), 1 << 63] {
        let disk = qcow2::open(Box::new(patched(&|q| be64(q, slot, entry)))).unwrap();
        let _ = disk.reader.read_at(0, &mut vec![0u8; 1 << 17]);
    }
}

#[test]
fn a_compressed_cluster_that_inflates_beyond_its_size_is_an_error() {
    for (zstd, fixture) in [(false, "qcow2-compressed.qcow2"), (true, "qcow2-zstd.qcow2")] {
        let good = unzst(fixture);
        let slot = qcow2_l2_entry_slot(&good, 0);
        let mut q = good.clone();
        let data_at = (q.len() as u64 + 511) & !511;
        q.resize(data_at as usize, 0);
        let bomb = bomb(zstd, 16 << 20);
        q.extend_from_slice(&bomb);
        q.resize(q.len() + 4096, 0);
        // Compressed: offset, and enough 512-byte sectors (at most 2 * 65536 / 512) to hold it.
        let sectors = (bomb.len() as u64).div_ceil(512).min(256) - 1;
        let shift = 62 - (16 - 8);
        be64(&mut q, slot, (1 << 62) | (sectors << shift) | data_at);
        let disk = qcow2::open(Box::new(q)).unwrap();
        let err = disk.reader.read_at(0, &mut [0u8; 16]).unwrap_err().to_string();
        assert!(err.contains("inflates beyond") || err.contains("inflate"), "{fixture}: {err}");
        // The other clusters are still readable.
        assert!(disk.reader.read_at(1 << 20, &mut [0u8; 16]).is_ok());
    }
}

fn vmdk_header(file: &[u8]) -> (u64, u64) {
    // (grain directory byte offset, grain size in bytes)
    let gd = u64::from_le_bytes(file[56..64].try_into().unwrap()) * 512;
    (gd, u64::from_le_bytes(file[20..28].try_into().unwrap()) * 512)
}

#[test]
fn hostile_vmdk_headers_and_tables_are_errors() {
    let good = unzst("vmdk-monolithicSparse.vmdk");
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = good.clone();
        f(&mut v);
        v
    };
    let open = |v: Vec<u8>| vmdk::from_sparse(Box::new(v));
    for grain in [0u64, 1, 7, 9, 12, 1 << 20, u64::MAX] {
        assert!(open(patched(&|v| le64(v, 20, grain))).is_err(), "grain {grain}");
    }
    for gtes in [0u32, u32::MAX, 1 << 17] {
        assert!(open(patched(&|v| le32(v, 44, gtes))).is_err(), "gtes {gtes}");
    }
    // A capacity whose grain directory would need gigabytes.
    for capacity in [1u64 << 50, u64::MAX, u64::MAX / 512 + 1] {
        assert!(open(patched(&|v| le64(v, 12, capacity))).is_err(), "capacity {capacity}");
    }
    assert!(open(patched(&|v| le64(v, 56, u64::MAX - 1))).is_err());
    assert!(open(patched(&|v| le64(v, 56, 1 << 40))).is_err());
    assert!(open(patched(&|v| v[73] = b'\r')).is_err() || good[8] & 1 == 0);
    assert!(open(patched(&|v| v.truncate(300))).is_err());

    let (gd, grain) = vmdk_header(&good);
    // Directory and table entries outside the file, and pointing at the directory itself.
    for target in [0xffff_ffffu32, 0x7fff_ffff, (good.len() / 512) as u32 + 100, (gd / 512) as u32] {
        let v = patched(&|v| le32(v, gd as usize, target));
        let disk = open(v).unwrap();
        let _ = disk.reader.read_at(0, &mut vec![0u8; 1 << 20]);
        let (table_at, _) = (le32_at(&good, gd as usize) as usize * 512, grain);
        let v = patched(&|v| le32(v, table_at, target));
        let disk = open(v).unwrap();
        let _ = disk.reader.read_at(0, &mut vec![0u8; 1 << 20]);
    }
}

fn le32_at(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

/// A grain directory at the end of the file, as VMware's `streamOptimized` exports have it:
/// the header says so, and the footer (header copy) sits 1024 bytes before the end.
#[test]
fn a_stream_optimized_footer_holds_the_directory() {
    let good = unzst("vmdk-streamOptimized.vmdk");
    let mut v = good.clone();
    let mut footer_header = v[..512].to_vec();
    le64(&mut v, 56, u64::MAX);
    let mut marker = vec![0u8; 512];
    marker[..8].copy_from_slice(&1u64.to_le_bytes());
    marker[12..16].copy_from_slice(&3u32.to_le_bytes());
    v.resize((v.len() + 511) & !511, 0);
    v.extend_from_slice(&marker);
    v.append(&mut footer_header);
    v.extend_from_slice(&[0u8; 512]);
    let disk = vmdk::from_sparse(Box::new(v.clone())).unwrap();
    assert_same("footer directory", &*disk.reader, &raw());
    // No footer where it should be: an error.
    v.truncate(v.len() - 512);
    assert!(vmdk::from_sparse(Box::new(v)).is_err());
}

#[test]
fn a_compressed_grain_that_inflates_beyond_its_size_is_an_error() {
    use std::io::Write;
    let good = unzst("vmdk-streamOptimized.vmdk");
    let gd = u64::from_le_bytes(good[56..64].try_into().unwrap()) as usize * 512;
    let grain_entry = (0..16)
        .map(|i| le32_at(&good, gd + i * 4) as usize * 512)
        .filter(|&table| table != 0)
        .find_map(|table| (0..512).map(|i| table + i * 4).find(|&e| le32_at(&good, e) > 1))
        .unwrap();
    let grain_at = le32_at(&good, grain_entry) as usize * 512;
    let lba = u64::from_le_bytes(good[grain_at..grain_at + 8].try_into().unwrap());
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(&vec![0u8; 16 << 20]).unwrap();
    let bomb = e.finish().unwrap();
    // A grain with a zlib stream that inflates to 16 MiB, appended and mapped in place of one.
    let mut v = good.clone();
    let at = (v.len() + 511) & !511;
    v.resize(at, 0);
    v.extend_from_slice(&lba.to_le_bytes());
    v.extend_from_slice(&(bomb.len() as u32).to_le_bytes());
    v.extend_from_slice(&bomb);
    v.resize(v.len() + 1024, 0);
    le32(&mut v, grain_entry, (at / 512) as u32);
    let disk = vmdk::from_sparse(Box::new(v)).unwrap();
    let err = disk.reader.read_at(lba * 512, &mut [0u8; 16]).unwrap_err().to_string();
    assert!(err.contains("inflates beyond") || err.contains("larger than a grain"), "{err}");
    // A grain whose marker names another grain is not the grain it is mapped to.
    let mut v = good.clone();
    le64(&mut v, grain_at, lba + 128);
    let disk = vmdk::from_sparse(Box::new(v)).unwrap();
    assert!(disk.reader.read_at(lba * 512, &mut [0u8; 16]).unwrap_err().to_string().contains("does not belong"));
}

#[test]
fn hostile_vhd_headers_and_tables_are_errors() {
    let good = unzst("vpc-dynamic.vhd");
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = good.clone();
        f(&mut v);
        v
    };
    let at = rd64(&good, 16) as usize;
    let fix = |v: &mut Vec<u8>| vhd_sum(&mut v[at..at + 1024], 36);
    let open = |v: Vec<u8>| vhd::open(Box::new(v));
    for block in [0u32, 1, 3, 511, 1 << 31, u32::MAX] {
        assert!(open(patched(&|v| {
            be32(v, at + 32, block);
            fix(v)
        }))
        .is_err());
    }
    for entries in [0u32, u32::MAX] {
        assert!(open(patched(&|v| {
            be32(v, at + 28, entries);
            fix(v)
        }))
        .is_err());
    }
    assert!(open(patched(&|v| {
        be64(v, at + 16, u64::MAX - 7);
        fix(v)
    }))
    .is_err());
    // A damaged checksum, and a size too big for the table.
    assert!(open(patched(&|v| v[at + 40] ^= 1)).is_err());
    assert!(open(patched(&|v| {
        be64(v, 48, 1 << 60);
        vhd_sum(&mut v[..512], 64)
    }))
    .is_err());
    // Table entries pointing outside the file or into the table itself.
    let table = rd64(&good, at + 16) as usize;
    for sector in [0u32, 0x7fff_ffff, 0xffff_fffe, (table / 512) as u32, (good.len() / 512) as u32] {
        let disk = open(patched(&|v| be32(v, table, sector))).unwrap();
        let _ = disk.reader.read_at(0, &mut vec![0u8; 4 << 20]);
    }
}

#[test]
fn a_fixed_vhd_is_the_file_minus_its_footer() {
    let dir = Dir::new("vhd-fixed");
    let mut data: Vec<u8> = (0..65536u32).map(|i| (i * 7) as u8).collect();
    let mut footer = [0u8; 512];
    footer[..8].copy_from_slice(b"conectix");
    footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    footer[48..56].copy_from_slice(&65536u64.to_be_bytes());
    footer[60..64].copy_from_slice(&2u32.to_be_bytes());
    vhd_sum(&mut footer, 64);
    let raw = data.clone();
    data.extend_from_slice(&footer);
    let disk = open_path(&dir.put("a.vhd", &data)).unwrap();
    assert_eq!(disk.reader.size(), 65536);
    assert_same_small(&*disk.reader, &raw);
    // A footer that claims more than the file holds, and one with a wrong checksum.
    footer[48..56].copy_from_slice(&(1u64 << 40).to_be_bytes());
    vhd_sum(&mut footer, 64);
    let mut bigger = raw.clone();
    bigger.extend_from_slice(&footer);
    assert!(error_of("b.vhd", bigger).contains("footer says"));
    footer[200] ^= 1;
    let mut damaged = raw.clone();
    damaged.extend_from_slice(&footer);
    let dir2 = Dir::new("vhd-fixed2");
    // Not a VHD at all, so not claimed (it is just raw data).
    assert!(open(&dir2.put("c.img", &damaged), &damaged[..512]).unwrap().is_none());
}

fn assert_same_small(reader: &dyn ReadAt, raw: &[u8]) {
    let mut out = vec![0u8; raw.len()];
    reader.read_at(0, &mut out).unwrap();
    assert!(out == raw);
}

#[test]
fn hostile_vhdx_headers_and_tables_are_errors() {
    let good = unzst("vhdx-dynamic.vhdx");
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = good.clone();
        f(&mut v);
        v
    };
    let open = |v: Vec<u8>| vhdx::open(Box::new(v));
    // Damaged headers: one bad header is survived, two are not.
    assert!(open(patched(&|v| v[65536 + 100] ^= 1)).is_ok());
    assert!(open(patched(&|v| {
        v[65536 + 100] ^= 1;
        v[131072 + 100] ^= 1;
    }))
    .is_err());
    assert!(open(patched(&|v| v[192 * 1024 + 100] ^= 1)).is_ok() || good[256 * 1024..].starts_with(b"regi"));
    assert!(open(patched(&|v| v.truncate(100_000))).is_err());
    // The BAT: entries outside the file, partially present, unknown states.
    let region = |id: [u8; 16]| {
        let table = &good[192 * 1024..];
        let entry = (0..le32_at(table, 8) as usize).map(|i| 16 + 32 * i).find(|&e| table[e..e + 16] == id).unwrap();
        u64::from_le_bytes(table[entry + 16..entry + 24].try_into().unwrap()) as usize
    };
    let bat = region([0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08]);
    let meta = region([0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E]);
    for entry in [6u64 | (1 << 50), 6 | (3 << 20), 6, 7 | (4 << 20), 4, 5, 6 | (bat as u64 >> 20 << 20)] {
        let disk = open(patched(&|v| le64(v, bat, entry))).unwrap();
        let mut out = vec![0u8; 64 << 20 >> 4];
        let _ = disk.reader.read_at(0, &mut out);
    }
    let disk = open(patched(&|v| le64(v, bat, 7 | (4 << 20)))).unwrap();
    let err = disk.reader.read_at(0, &mut [0u8; 16]).unwrap_err().to_string();
    assert!(err.contains("partially present"), "{err}");
    // Block size and virtual size fields (in the metadata, which no checksum covers).
    let item = |id: [u8; 16]| {
        let entry = (0..20).map(|i| meta + 32 + 32 * i).find(|&e| good[e..e + 16] == id).unwrap();
        meta + le32_at(&good, entry + 16) as usize
    };
    let params = item([0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B]);
    for block in [0u32, 1, 3 << 20, 1 << 31, u32::MAX] {
        assert!(open(patched(&|v| le32(v, params, block))).is_err(), "block {block}");
    }
    let size = item([0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8]);
    for s in [u64::MAX, 1 << 62, 1 << 50] {
        assert!(open(patched(&|v| le64(v, size, s))).is_err(), "size {s}");
    }
    let sector = item([0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F]);
    assert!(open(patched(&|v| le32(v, sector, 0))).is_err());
    // A header with an unknown version, even with a good checksum.
    assert!(open(patched(&|v| {
        for at in [65536, 131072] {
            v[at + 66] = 9;
            vhdx_crc(&mut v[at..at + 4096]);
        }
    }))
    .is_err());
}

#[test]
fn hostile_vdi_headers_and_tables_are_errors() {
    let good = unzst("vdi-dynamic.vdi");
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = good.clone();
        f(&mut v);
        v
    };
    let open = |v: Vec<u8>| vdi::open(Box::new(v));
    for block in [0u32, 1, 511, 513, 1 << 31, u32::MAX] {
        assert!(open(patched(&|v| le32(v, 376, block))).is_err(), "block {block}");
    }
    for blocks in [0u32, u32::MAX] {
        assert!(open(patched(&|v| le32(v, 384, blocks))).is_err(), "blocks {blocks}");
    }
    assert!(open(patched(&|v| le32(v, 340, u32::MAX))).is_err());
    assert!(open(patched(&|v| le64(v, 368, u64::MAX))).is_err());
    assert!(open(patched(&|v| v.truncate(200))).is_err());
    assert!(open(patched(&|v| le32(v, 64, 0))).is_err());
    let map = le32_at(&good, 340) as usize;
    for entry in [0u32, 0x7fff_ffff, 0xffff_fffd, 1 << 20] {
        let disk = open(patched(&|v| le32(v, map, entry))).unwrap();
        let _ = disk.reader.read_at(0, &mut vec![0u8; 2 << 20]);
    }
}

/// Reads a few places of a disk that may be hostile: it must return, with data or an error.
fn exercise(reader: &dyn ReadAt, rng: &mut Rng) {
    let size = reader.size();
    let mut buf = vec![0u8; 70_000];
    for _ in 0..6 {
        let len = (1 + rng.below(buf.len() as u64)).min(size) as usize;
        if len == 0 {
            break;
        }
        let at = if rng.below(2) == 0 { rng.below(1 << 20) } else { rng.below(size) };
        let _ = reader.read_at(at.min(size - len as u64), &mut buf[..len]);
    }
    let _ = reader.read_at(size, &mut buf[..1]);
    let _ = reader.read_at(u64::MAX, &mut buf[..1]);
}

/// Thousands of byte flips, extreme values and truncations of a real file: no panic, no hang.
fn mutate(
    original: &[u8],
    hot: usize,
    rounds: usize,
    seed: u64,
    mut open: impl FnMut(Vec<u8>) -> Option<Box<dyn ReadAt>>,
) {
    let mut rng = Rng(seed);
    let hot = hot.min(original.len()).max(1);
    for round in 0..rounds {
        let mut data = original.to_vec();
        match round % 5 {
            0 => {
                for _ in 0..1 + rng.below(3) {
                    let at = rng.below(512.min(hot as u64)) as usize;
                    data[at] = rng.next() as u8;
                }
            }
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let at = rng.below(hot as u64) as usize;
                    data[at] ^= 1 << rng.below(8);
                }
            }
            2 => data.truncate(rng.below(data.len() as u64) as usize),
            _ => {
                // An extreme value over a 4 or 8 byte field somewhere in the headers or tables.
                let at = rng.below(hot as u64 - hot.min(8) as u64 + 1) as usize;
                let value = [0u64, u64::MAX, 0x7fff_ffff, 1 << 31, 1 << 32, 1 << 62, 0xffff_ffff_0000_0000, 1]
                    [rng.below(8) as usize];
                let n = if rng.below(2) == 0 { 4 } else { 8 };
                let bytes = if rng.below(2) == 0 { value.to_le_bytes() } else { value.to_be_bytes() };
                let slice = if n == 4 { &bytes[..4] } else { &bytes[..] };
                let end = (at + n).min(data.len());
                data[at..end].copy_from_slice(&slice[..end - at]);
            }
        }
        if let Some(reader) = open(data) {
            exercise(&*reader, &mut rng);
        }
    }
}

fn mutate_format(fixture: &str, hot: usize, rounds: usize, opener: fn(Data) -> io::Result<Disk>) {
    let original = unzst(fixture);
    mutate(&original, hot, rounds, 0x5eed ^ fixture.len() as u64, |data| {
        opener(Box::new(data)).ok().map(|d| Box::new(d.reader) as Box<dyn ReadAt>)
    });
}

// Arc<dyn ReadAt + Send + Sync> is a ReadAt (see nixcavate-fs), so it boxes as one.

#[test]
fn mutated_qcow2_files_never_panic() {
    for fixture in [
        "qcow2-v3.qcow2",
        "qcow2-compressed.qcow2",
        "qcow2-zstd.qcow2",
        "qcow2-extl2.qcow2",
        "qcow2-v2.qcow2",
        "qcow2-512.qcow2",
    ] {
        mutate_format(fixture, 600_000, 1500, qcow2::open);
    }
}

#[test]
fn mutated_vmdk_files_never_panic() {
    for fixture in ["vmdk-monolithicSparse.vmdk", "vmdk-streamOptimized.vmdk"] {
        mutate_format(fixture, 400_000, 1500, vmdk::from_sparse);
    }
    // Descriptors, with extents beside them.
    let dir = Dir::new("mutate-vmdk");
    dir.stage("vmdk-twoGbMaxExtentSparse-s001.vmdk");
    dir.put("vmdk-monolithicFlat-flat.vmdk", &vec![0u8; 8 << 20]);
    for fixture in ["vmdk-twoGbMaxExtentSparse.vmdk", "vmdk-monolithicFlat.vmdk"] {
        let original = unzst(fixture);
        mutate(&original, 512, 800, 77, |data| {
            let path = dir.put("d.vmdk", &data);
            let head = &data[..data.len().min(512)];
            open(&path, head).ok().flatten().map(|d| Box::new(d.reader) as Box<dyn ReadAt>)
        });
    }
}

#[test]
fn mutated_vhd_files_never_panic() {
    mutate_format("vpc-dynamic.vhd", 20_000, 2000, vhd::open);
    // Fixed disks are found by their footer: mutate a small one in its file.
    let mut data: Vec<u8> = (0..16384u32).map(|i| (i * 7) as u8).collect();
    let mut footer = [0u8; 512];
    footer[..8].copy_from_slice(b"conectix");
    footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    footer[48..56].copy_from_slice(&16384u64.to_be_bytes());
    footer[60..64].copy_from_slice(&2u32.to_be_bytes());
    vhd_sum(&mut footer, 64);
    data.extend_from_slice(&footer);
    let dir = Dir::new("mutate-vhd-fixed");
    let mut rng = Rng(5);
    for round in 0..400 {
        let mut d = data.clone();
        let at = d.len() - 512 + rng.below(512) as usize;
        if round % 2 == 0 {
            d[at] ^= 1 << rng.below(8);
        } else {
            d.truncate(d.len() - rng.below(600) as usize);
        }
        let path = dir.put("f.vhd", &d);
        if let Ok(Some(disk)) = open(&path, &d[..d.len().min(512)]) {
            exercise(&*disk.reader, &mut rng);
        }
    }
}

#[test]
fn mutated_vhdx_files_never_panic() {
    // Headers and regions live in the first 320 KiB, the metadata and BAT in the next MiBs.
    mutate_format("vhdx-dynamic.vhdx", 4 << 20, 1500, vhdx::open);
    mutate_format("vhdx-1m.vhdx", 4 << 20, 500, vhdx::open);
}

#[test]
fn mutated_vdi_files_never_panic() {
    mutate_format("vdi-dynamic.vdi", 8192, 2000, vdi::open);
    mutate_format("vdi-static.vdi", 8192, 500, vdi::open);
}

/// Readers are shared by the tasks of a run: concurrent reads must agree.
#[test]
fn concurrent_reads_of_compressed_disks_agree() {
    let raw = raw();
    for fixture in ["qcow2-compressed.qcow2", "qcow2-zstd.qcow2", "vmdk-streamOptimized.vmdk"] {
        let dir = Dir::new(&format!("threads-{}", &fixture[..fixture.len() - 6]));
        let disk = open_path(&dir.stage(fixture)).unwrap();
        std::thread::scope(|scope| {
            for t in 0..4u64 {
                let (reader, raw) = (&disk.reader, &raw);
                scope.spawn(move || {
                    let mut rng = Rng(1 + t);
                    for _ in 0..300 {
                        let len = 1 + rng.below(100_000) as usize;
                        let from = rng.below((raw.len() - len) as u64) as usize;
                        let mut out = vec![0u8; len];
                        reader.read_at(from as u64, &mut out).unwrap();
                        assert!(out == raw[from..from + len]);
                    }
                });
            }
        });
    }
}

/// Reads a whole real disk (corpus data, not in the repository) and compares it with its raw
/// original, byte for byte; prints the sequential read speed. Run in release mode:
/// `NIXCAVATE_VDISK=<disk> [NIXCAVATE_VDISK_RAW=<raw>] [NIXCAVATE_VDISK_DUMP=<file>]
///  cargo test --release -p nixcavate-source corpus_disk -- --ignored --nocapture`
#[test]
#[ignore = "needs corpus files, named by environment variables"]
fn corpus_disk_is_read_whole() {
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    let Some(disk) = std::env::var_os("NIXCAVATE_VDISK") else { return };
    let started = std::time::Instant::now();
    // A raw file is read through the plain mapping, as the baseline for the speeds.
    let reader: crate::image::Shared = match open_path(Path::new(&disk)) {
        Ok(opened) => {
            println!("opened in {:?}: {:?}", started.elapsed(), opened.notes);
            opened.reader
        }
        Err(e) => {
            println!("not a virtual disk ({e}): read as raw");
            Arc::new(crate::image::Mapped(map(Path::new(&disk)).unwrap()))
        }
    };
    let raw = std::env::var_os("NIXCAVATE_VDISK_RAW").map(|p| std::fs::File::open(p).unwrap());
    let mut dump =
        std::env::var_os("NIXCAVATE_VDISK_DUMP").map(|p| std::io::BufWriter::new(std::fs::File::create(p).unwrap()));
    let raw_len = raw.as_ref().map(|f| f.metadata().unwrap().len());
    let size = reader.size();
    println!("virtual size {size}, raw size {raw_len:?}");
    let (mut at, mut buf, mut want, mut bad) = (0u64, vec![0u8; 4 << 20], vec![0u8; 4 << 20], 0u64);
    let started = std::time::Instant::now();
    while at < size {
        let n = buf.len().min((size - at) as usize);
        reader.read_at(at, &mut buf[..n]).unwrap_or_else(|e| panic!("read at {at}: {e}"));
        if let Some(d) = dump.as_mut() {
            d.write_all(&buf[..n]).unwrap();
        }
        if let (Some(f), Some(len)) = (&raw, raw_len) {
            let m = n.min(len.saturating_sub(at) as usize);
            f.read_exact_at(&mut want[..m], at).unwrap();
            want[m..n].fill(0);
            if buf[..n] != want[..n] {
                bad += 1;
                println!("MISMATCH in the 4 MiB at {at}");
            }
        }
        at += n as u64;
    }
    let secs = started.elapsed().as_secs_f64();
    println!("read {size} bytes in {secs:.2} s = {:.0} MiB/s (comparison included if a raw file was given); mismatching blocks: {bad}", size as f64 / 1048576.0 / secs);
    assert_eq!(bad, 0);
}

/// A real multi-extent disk against ranges `qemu-img dd` wrote: `NIXCAVATE_VDISK=<descriptor>
/// NIXCAVATE_VDISK_RANGES=<dir of r<MiB index>.bin files of 1 MiB>`. Also lists the partitions
/// and the volumes found on the disk.
#[test]
#[ignore = "needs corpus files, named by environment variables"]
fn corpus_disk_ranges_match_qemu() {
    let (Some(disk), Some(ranges)) = (std::env::var_os("NIXCAVATE_VDISK"), std::env::var_os("NIXCAVATE_VDISK_RANGES"))
    else {
        return;
    };
    let opened = open_path(Path::new(&disk)).unwrap();
    println!("{:?}", opened.notes);
    let reader = opened.reader;
    let parts = crate::image::partitions::scan(&reader);
    for part in &parts {
        println!("partition {} {} at {} for {} bytes", part.index, part.type_name, part.start, part.len);
        let slice = nixcavate_fs::Slice { inner: reader.clone(), start: part.start, len: part.len };
        for volume in crate::image::open_volumes(slice) {
            println!("  volume: {}", volume.kind());
        }
    }
    let (mut compared, mut bad) = (0, 0);
    for entry in std::fs::read_dir(ranges).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(index) =
            name.strip_prefix('r').and_then(|n| n.strip_suffix(".bin")).and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        let want = std::fs::read(&path).unwrap();
        let mut got = vec![0u8; want.len()];
        reader.read_at(index << 20, &mut got).unwrap();
        compared += 1;
        if got != want {
            bad += 1;
            println!("MISMATCH at MiB {index}");
        }
    }
    println!("compared {compared} ranges of 1 MiB against qemu-img: {bad} mismatches");
    assert!(compared >= 20 && bad == 0);
}

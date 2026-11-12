//! Partition tables: GPT and MBR, found by signature on a [`ReadAt`].
//!
//! Written from the UEFI specification, "GUID Partition Table (GPT) Disk Layout" (header,
//! entry array, CRC-32 over both, backup header in the last LBA), and from the classic MBR
//! layout (four 16-byte entries at offset 446, signature 0x55AA; an extended partition is a
//! chain of EBRs whose first entry is a logical partition relative to the EBR and whose second
//! entry links to the next EBR relative to the start of the extended partition).
//! Signatures for LUKS (LUKS1/LUKS2 on-disk specification: `LUKS\xba\xbe` at 0), LVM2
//! (`LABELONE` label with `LVM2 001` in one of the first four sectors) and Linux md RAID
//! (superblock magic 0xa92b4efc, version 0.90 near the end, 1.0 at the end, 1.1 at 0 and 1.2
//! at 4 KiB) come from their public documentation. An LVM2 volume is read by `lvm`; LUKS and
//! RAID members are only named.
//!
//! Nothing here trusts the disk: every offset is checked against the image size, counts are
//! capped, and extended-partition chains stop at a revisited EBR.

use nixcavate_fs::{le32, le64, ReadAt, Slice};
use std::collections::HashSet;

/// Why an LVM2 physical volume is not a filesystem; `lvm` reads these.
pub const LVM_REASON: &str = "LVM2 physical volume";

/// One partition of a disk image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// 1-based slot: the GPT entry number, 1 to 4 for MBR primaries, 5 and up for logicals.
    /// A disk with no table is one partition with index 1.
    pub index: usize,
    /// Byte offset in the image.
    pub start: u64,
    pub len: u64,
    /// `linux`, `apple_apfs`, `efi_system`, `lvm`, `swap`, ... or the raw type id.
    pub type_name: String,
    /// Set when the contents are recognised but are not a filesystem: LUKS and RAID members
    /// (not read) and LVM2 physical volumes ([`LVM_REASON`], read through their logical volumes).
    pub unsupported: Option<&'static str>,
}

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// Entry arrays are 128 entries of 128 bytes in practice; this is the most we will read.
const MAX_GPT_ENTRIES: u64 = 4096;
const MAX_GPT_ENTRY_SIZE: u64 = 1024;
/// Logical partitions followed in one extended chain.
const MAX_LOGICAL: usize = 128;

/// Lists the partitions of `image`. An image with no table whose start is a filesystem (or an
/// encrypted / LVM / RAID volume) is one partition covering all of it. Empty when nothing is
/// recognised.
pub fn scan(image: &dyn ReadAt) -> Vec<Partition> {
    let size = image.size();
    let mut parts = if let Some(parts) = gpt(image) {
        parts
    } else if let Some(name) = filesystem_signature(image) {
        vec![Partition { index: 1, start: 0, len: size, type_name: name.into(), unsupported: None }]
    } else if let Some(parts) = mbr(image) {
        parts
    } else if unsupported_signature(image).is_some() {
        // Named by the loop below.
        vec![Partition { index: 1, start: 0, len: size, type_name: "raw".into(), unsupported: None }]
    } else {
        Vec::new()
    };
    for part in &mut parts {
        part.unsupported = unsupported_signature(&Slice { inner: image, start: part.start, len: part.len });
    }
    parts
}

/// The filesystem whose superblock signature sits where `reader` starts: `ext4` (any ext2/3/4,
/// magic 0xEF53 at 1080), `xfs` (`XFSB` at 0) or `apfs` (`NXSB` at 32).
pub fn filesystem_signature(reader: &dyn ReadAt) -> Option<&'static str> {
    let head = read_vec(reader, 0, 1082.min(reader.size()))?;
    if head.starts_with(b"XFSB") {
        Some("xfs")
    } else if head.get(32..36) == Some(b"NXSB") {
        Some("apfs")
    } else if head.get(1080..1082) == Some(&[0x53, 0xEF]) {
        Some("ext4")
    } else {
        None
    }
}

/// LUKS, LVM2 and software RAID members, by signature.
pub fn unsupported_signature(reader: &dyn ReadAt) -> Option<&'static str> {
    let size = reader.size();
    let head = read_vec(reader, 0, 8192.min(size))?;
    if head.starts_with(b"LUKS\xba\xbe") {
        return Some("LUKS encrypted volume");
    }
    if (0..4).any(|sector| head.get(sector * 512..sector * 512 + 32).is_some_and(is_lvm_label)) {
        return Some(LVM_REASON);
    }
    let md = |at: u64| read_vec(reader, at, 4).is_some_and(|m| m == 0xa92b_4efcu32.to_le_bytes());
    // 1.1 at the start, 1.2 at 4 KiB, 1.0 8 KiB from the end (4 KiB aligned), 0.90 in the
    // last 64 KiB-aligned block.
    let ends = [(size >= 8192).then(|| (size - 8192) & !4095), (size >= 65536).then(|| (size & !65535) - 65536)];
    if md(0) || md(4096) || ends.iter().flatten().any(|&at| md(at)) {
        return Some("Linux software RAID member");
    }
    None
}

fn is_lvm_label(sector: &[u8]) -> bool {
    sector.starts_with(b"LABELONE") && sector.get(24..32) == Some(b"LVM2 001")
}

fn read_vec(reader: &dyn ReadAt, offset: u64, len: u64) -> Option<Vec<u8>> {
    if offset.checked_add(len)? > reader.size() || len > 64 << 20 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_at(offset, &mut buf).ok()?;
    Some(buf)
}

/// CRC-32 (IEEE, as zlib uses), which GPT uses for its header and entry array.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 { crc >> 1 ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// A GPT, from the primary header or, when that is damaged, the backup in the last sector.
/// Both 512- and 4096-byte sectors are tried; the header's own LBA field must agree with
/// where it was found, which rules out the wrong sector size.
fn gpt(image: &dyn ReadAt) -> Option<Vec<Partition>> {
    let size = image.size();
    for backup in [false, true] {
        for sector in [512u64, 4096] {
            let offset = if backup { (size / sector * sector).checked_sub(sector) } else { Some(sector) };
            if let Some(parts) = offset.and_then(|offset| gpt_at(image, offset, sector)) {
                return Some(parts);
            }
        }
    }
    None
}

fn gpt_at(image: &dyn ReadAt, offset: u64, sector: u64) -> Option<Vec<Partition>> {
    let size = image.size();
    let mut header = read_vec(image, offset, 92)?;
    if &header[..8] != GPT_SIGNATURE {
        return None;
    }
    let header_len = le32(&header, 12) as u64;
    if !(92..=sector).contains(&header_len) {
        return None;
    }
    header = read_vec(image, offset, header_len)?;
    let stored = le32(&header, 16);
    header[16..20].fill(0);
    if crc32(&header) != stored || le64(&header, 24) != offset / sector {
        return None;
    }
    let (first_lba, count, entry_size) = (le64(&header, 72), le32(&header, 80) as u64, le32(&header, 84) as u64);
    if count > MAX_GPT_ENTRIES || !(128..=MAX_GPT_ENTRY_SIZE).contains(&entry_size) || entry_size % 8 != 0 {
        return None;
    }
    let array = read_vec(image, first_lba.checked_mul(sector)?, count * entry_size)?;
    if crc32(&array) != le32(&header, 88) {
        return None;
    }
    let mut parts = Vec::new();
    for (slot, entry) in array.chunks_exact(entry_size as usize).enumerate() {
        let type_guid = &entry[..16];
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }
        let (first, last) = (le64(entry, 32), le64(entry, 40));
        let start = first.saturating_mul(sector);
        let Some(end) = last.checked_add(1).and_then(|end| end.checked_mul(sector)) else { continue };
        if last < first || start >= size {
            continue;
        }
        // A truncated image can end inside the last partition.
        let len = end.min(size) - start;
        parts.push(Partition { index: slot + 1, start, len, type_name: gpt_type(type_guid), unsupported: None });
    }
    Some(parts)
}

/// The text form of a GUID as stored on disk (first three fields little endian).
fn guid_string(g: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10..16].iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn gpt_type(guid: &[u8]) -> String {
    let text = guid_string(guid);
    let name = match text.as_str() {
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "linux",
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "efi_system",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "lvm",
        "a19d880f-05fc-4d3b-a006-743f0f84911e" => "linux_raid",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "apple_apfs",
        "48465300-0000-11aa-aa11-00306543ecac" => "apple_hfs",
        "21686148-6449-6e6f-744e-656564454649" => "bios_boot",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "microsoft_basic_data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "microsoft_reserved",
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "linux_home",
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" | "b921b045-1df0-41c3-af44-4c6f280d3fae" => "linux_root",
        _ => return text,
    };
    name.into()
}

fn mbr_type(id: u8) -> String {
    match id {
        0x83 => "linux",
        0x82 => "swap",
        0x8e => "lvm",
        0xfd => "linux_raid",
        0xee => "gpt_protective",
        0xef => "efi_system",
        0xaf => "apple_hfs",
        0x07 => "ntfs_exfat",
        0x01 | 0x04 | 0x06 | 0x0b | 0x0c | 0x0e => "fat",
        _ => return format!("0x{id:02x}"),
    }
    .into()
}

fn is_extended(id: u8) -> bool {
    matches!(id, 0x05 | 0x0f | 0x85)
}

/// One MBR / EBR table entry: (type id, start LBA, sector count).
fn mbr_entries(sector: &[u8]) -> Option<[(u8, u32, u32); 4]> {
    if sector.len() < 512 || sector[510..512] != [0x55, 0xaa] {
        return None;
    }
    let mut out = [(0, 0, 0); 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let entry = &sector[446 + i * 16..462 + i * 16];
        // The boot flag is 0x80 or 0; anything else means this is boot code, not a table.
        if entry[0] != 0 && entry[0] != 0x80 {
            return None;
        }
        *slot = (entry[4], le32(entry, 8), le32(entry, 12));
    }
    Some(out)
}

fn mbr(image: &dyn ReadAt) -> Option<Vec<Partition>> {
    const SECTOR: u64 = 512;
    let size = image.size();
    let entries = mbr_entries(&read_vec(image, 0, 512)?)?;
    let used = |&(id, start, count): &(u8, u32, u32)| id != 0 && count > 0 && start as u64 * SECTOR < size;
    if !entries.iter().any(used) {
        return None;
    }
    let make = |index: usize, start: u64, count: u32, id: u8| Partition {
        index,
        start: start * SECTOR,
        len: (count as u64 * SECTOR).min(size - start * SECTOR),
        type_name: mbr_type(id),
        unsupported: None,
    };
    let mut parts = Vec::new();
    let mut extended = None;
    for (i, entry) in entries.iter().enumerate().filter(|(_, e)| used(e)) {
        let &(id, start, count) = entry;
        if is_extended(id) {
            extended.get_or_insert(start as u64);
        } else {
            parts.push(make(i + 1, start as u64, count, id));
        }
    }
    if let Some(base) = extended {
        let mut ebr = base;
        let mut logical = 5;
        let mut seen = HashSet::new();
        while parts.len() < 4 + MAX_LOGICAL && seen.insert(ebr) {
            let Some(table) = ebr.checked_mul(SECTOR).and_then(|at| read_vec(image, at, 512)) else { break };
            let Some(entries) = mbr_entries(&table) else { break };
            let (id, rel, count) = entries[0];
            let start = ebr + rel as u64;
            if id != 0 && count > 0 && start * SECTOR < size {
                parts.push(make(logical, start, count, id));
                logical += 1;
            }
            let (link, rel, _) = entries[1];
            if !is_extended(link) || rel == 0 {
                break;
            }
            ebr = base + rel as u64;
        }
    }
    parts.sort_by_key(|p| p.index);
    Some(parts)
}

#[cfg(test)]
pub(crate) mod testing {
    use nixcavate_fs::ReadAt;
    use std::io;
    use std::path::Path;

    /// A large image that is zero except for a few stored pieces: the table sectors of a real
    /// disk, saved as `u64 total size` then `(u64 offset, u64 length, bytes)` records.
    pub struct Sparse {
        pub size: u64,
        pub pieces: Vec<(u64, Vec<u8>)>,
    }

    impl Sparse {
        pub fn load(name: &str) -> Sparse {
            let data =
                std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image").join(name)).unwrap();
            let num = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
            let mut pieces = Vec::new();
            let mut at = 8;
            while at < data.len() {
                let (offset, len) = (num(at), num(at + 8) as usize);
                pieces.push((offset, data[at + 16..at + 16 + len].to_vec()));
                at += 16 + len;
            }
            Sparse { size: num(0), pieces }
        }
    }

    impl ReadAt for Sparse {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            if offset + buf.len() as u64 > self.size {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf.fill(0);
            for (start, bytes) in &self.pieces {
                let (lo, hi) = (offset.max(*start), (offset + buf.len() as u64).min(start + bytes.len() as u64));
                if lo < hi {
                    buf[(lo - offset) as usize..(hi - offset) as usize]
                        .copy_from_slice(&bytes[(lo - start) as usize..(hi - start) as usize]);
                }
            }
            Ok(())
        }

        fn size(&self) -> u64 {
            self.size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Sparse;
    use super::*;
    use nixcavate_fs::Bytes;

    const MIB: u64 = 1 << 20;

    fn summary(parts: &[Partition]) -> Vec<(usize, u64, u64, &str)> {
        parts.iter().map(|p| (p.index, p.start, p.len, p.type_name.as_str())).collect()
    }

    #[test]
    fn gpt_with_512_byte_sectors() {
        let image = Sparse::load("gpt512.parts");
        let parts = scan(&image);
        assert_eq!(
            summary(&parts),
            [
                (1, 2048 * 512, 8 * MIB, "efi_system"),
                (2, 18432 * 512, 16 * MIB, "linux"),
                (3, 51200 * 512, 8 * MIB, "lvm"),
                (4, 67584 * 512, 8 * MIB, "apple_apfs"),
                (5, 83968 * 512, 4 * MIB, "swap"),
            ]
        );
        assert!(parts.iter().all(|p| p.unsupported.is_none()));
    }

    #[test]
    fn gpt_with_4096_byte_sectors() {
        let parts = scan(&Sparse::load("gpt4096.parts"));
        assert_eq!(
            summary(&parts),
            [
                (1, 256 * 4096, 8 * MIB, "efi_system"),
                (2, 2304 * 4096, 16 * MIB, "linux"),
                (3, 6400 * 4096, 8 * MIB, "apple_apfs")
            ]
        );
    }

    #[test]
    fn damaged_primary_header_falls_back_to_the_backup() {
        for name in ["gpt512.parts", "gpt4096.parts"] {
            let good = scan(&Sparse::load(name));
            let mut image = Sparse::load(name);
            // Wipe the primary header (the second sector or the second 4 KiB sector).
            let sector = if name.contains("4096") { 4096 } else { 512 };
            image.pieces.push((sector, vec![0xffu8; 92]));
            // Pieces are applied in order, so the later one wins.
            let mut check = vec![0u8; 8];
            image.read_at(sector, &mut check).unwrap();
            assert_eq!(check, [0xff; 8]);
            assert_eq!(scan(&image), good, "{name}");
        }
    }

    #[test]
    fn damaged_entry_array_falls_back_to_the_backup() {
        let good = scan(&Sparse::load("gpt512.parts"));
        let mut image = Sparse::load("gpt512.parts");
        image.pieces.push((1024 + 32, vec![0x11; 8])); // inside the first entry of the primary array
        assert_eq!(scan(&image), good);
    }

    #[test]
    fn both_gpt_headers_damaged_leaves_the_protective_mbr() {
        let mut image = Sparse::load("gpt512.parts");
        image.pieces.push((512, vec![0u8; 92]));
        image.pieces.push((image.size - 512, vec![0u8; 92]));
        let parts = scan(&image);
        assert_eq!(summary(&parts), [(1, 512, 64 * MIB - 512, "gpt_protective")]);
    }

    #[test]
    fn mbr_with_extended_partitions() {
        let parts = scan(&Sparse::load("mbr.parts"));
        assert_eq!(
            summary(&parts),
            [
                (1, 2048 * 512, 8192 * 512, "linux"),
                (2, 10240 * 512, 8192 * 512, "swap"),
                (3, 18432 * 512, 8192 * 512, "lvm"),
                (5, 28672 * 512, 8192 * 512, "linux"),
                (6, 38912 * 512, 16384 * 512, "linux_raid"),
            ]
        );
    }

    /// An MBR image with an extended partition at sector 100, whose chain is built by `link`.
    fn chain(links: &[(usize, u32)]) -> Vec<Partition> {
        let mut image = vec![0u8; 4 << 20];
        let entry = |image: &mut Vec<u8>, sector: usize, slot: usize, id: u8, start: u32, count: u32| {
            let at = sector * 512 + 446 + slot * 16;
            image[at + 4] = id;
            image[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            image[at + 12..at + 16].copy_from_slice(&count.to_le_bytes());
            image[sector * 512 + 510..sector * 512 + 512].copy_from_slice(&[0x55, 0xaa]);
        };
        entry(&mut image, 0, 0, 0x05, 100, 4000);
        // `links`: (EBR sector, relative start of the link to the next EBR, 0 for none).
        for &(sector, next) in links {
            entry(&mut image, sector, 0, 0x83, 1, 10);
            if next != 0 {
                entry(&mut image, sector, 1, 0x05, next, 100);
            }
        }
        scan(&Bytes(&image))
    }

    #[test]
    fn extended_chains_are_followed_and_loops_terminate() {
        let linear = chain(&[(100, 200), (300, 0)]);
        assert_eq!(summary(&linear), [(5, 101 * 512, 10 * 512, "linux"), (6, 301 * 512, 10 * 512, "linux")]);
        // The second EBR links to itself, and to the first one.
        assert_eq!(chain(&[(100, 200), (300, 200)]).len(), 2);
        assert_eq!(chain(&[(100, 200), (300, 1)]).len(), 2);
        // A link to an unreadable place just ends the chain.
        assert_eq!(chain(&[(100, 0x7fff_ffff)]).len(), 1);
    }

    #[test]
    fn bare_filesystems() {
        let mut ext = vec![0u8; 4096];
        ext[1080..1082].copy_from_slice(&[0x53, 0xef]);
        let parts = scan(&Bytes(&ext));
        assert_eq!(summary(&parts), [(1, 0, 4096, "ext4")]);

        let mut xfs = vec![0u8; 4096];
        xfs[..4].copy_from_slice(b"XFSB");
        assert_eq!(scan(&Bytes(&xfs))[0].type_name, "xfs");

        let mut apfs = vec![0u8; 4096];
        apfs[32..36].copy_from_slice(b"NXSB");
        assert_eq!(scan(&Bytes(&apfs))[0].type_name, "apfs");

        assert!(scan(&Bytes(&[0u8; 4096])).is_empty());
        assert!(scan(&Bytes(&[])).is_empty());
    }

    #[test]
    fn unsupported_volumes_are_named() {
        let mut luks = vec![0u8; 1 << 20];
        luks[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x02");
        assert_eq!(scan(&Bytes(&luks))[0].unsupported, Some("LUKS encrypted volume"));

        let mut lvm = vec![0u8; 1 << 20];
        lvm[512..520].copy_from_slice(b"LABELONE");
        lvm[512 + 24..512 + 32].copy_from_slice(b"LVM2 001");
        assert_eq!(scan(&Bytes(&lvm))[0].unsupported, Some("LVM2 physical volume"));

        let magic = 0xa92b_4efcu32.to_le_bytes();
        for at in [0usize, 4096, (1 << 20) - 8192, (1 << 20) - 65536] {
            let mut raid = vec![0u8; 1 << 20];
            raid[at..at + 4].copy_from_slice(&magic);
            assert_eq!(scan(&Bytes(&raid))[0].unsupported, Some("Linux software RAID member"), "at {at}");
        }

        // A GPT partition holding LUKS: reported on that partition only.
        let mut image = Sparse::load("gpt512.parts");
        let mut header = vec![0u8; 8];
        header.copy_from_slice(b"LUKS\xba\xbe\x00\x01");
        image.pieces.push((18432 * 512, header));
        let parts = scan(&image);
        assert_eq!(parts[1].unsupported, Some("LUKS encrypted volume"));
        assert!(parts[0].unsupported.is_none() && parts[2].unsupported.is_none());
    }

    #[test]
    fn one_overflowing_gpt_entry_is_skipped_not_the_table() {
        let mut image = vec![0u8; 1 << 20];
        let linux = [0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4];
        let entry = |image: &mut Vec<u8>, slot: usize, first: u64, last: u64| {
            let at = 1024 + slot * 128;
            image[at..at + 16].copy_from_slice(&linux);
            image[at + 32..at + 40].copy_from_slice(&first.to_le_bytes());
            image[at + 40..at + 48].copy_from_slice(&last.to_le_bytes());
        };
        entry(&mut image, 0, 34, u64::MAX); // last + 1 overflows
        entry(&mut image, 1, 100, 199);
        let header = 512;
        image[header..header + 8].copy_from_slice(GPT_SIGNATURE);
        image[header + 12..header + 16].copy_from_slice(&92u32.to_le_bytes());
        image[header + 24..header + 32].copy_from_slice(&1u64.to_le_bytes());
        image[header + 72..header + 80].copy_from_slice(&2u64.to_le_bytes());
        image[header + 80..header + 84].copy_from_slice(&4u32.to_le_bytes());
        image[header + 84..header + 88].copy_from_slice(&128u32.to_le_bytes());
        let array = crc32(&image[1024..1024 + 4 * 128]);
        image[header + 88..header + 92].copy_from_slice(&array.to_le_bytes());
        let sum = crc32(&image[header..header + 92]);
        image[header + 16..header + 20].copy_from_slice(&sum.to_le_bytes());
        assert_eq!(summary(&scan(&Bytes(&image))), [(2, 100 * 512, 100 * 512, "linux")]);
    }

    #[test]
    fn hostile_tables_do_not_panic() {
        for name in ["gpt512.parts", "gpt4096.parts", "mbr.parts"] {
            let base = Sparse::load(name);
            for (piece, len) in base.pieces.iter().map(|(_, d)| d.len()).enumerate() {
                for i in (0..len).step_by(7) {
                    for mask in [0x01u8, 0x80, 0xff] {
                        let mut image = Sparse::load(name);
                        image.pieces[piece].1[i] ^= mask;
                        scan(&image);
                    }
                }
            }
            for size in [0u64, 1, 511, 512, 1024, 4096, 8192, 1 << 20] {
                let mut image = Sparse::load(name);
                image.size = size;
                image.pieces.retain(|(off, d)| off + d.len() as u64 <= size);
                scan(&image);
            }
        }
    }
}

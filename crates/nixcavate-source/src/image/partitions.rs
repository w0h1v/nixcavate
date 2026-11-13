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
//! at 4 KiB) come from their public documentation. An LVM2 volume is read by `lvm` and a RAID
//! member by `md`; LUKS is only named.
//!
//! BSD disklabels and Solaris VTOCs split one slice (or a whole disk) into the partitions that
//! hold filesystems: FreeBSD's `bsdlabel` (magic 0x82564557 in sector 1 of an MBR slice of
//! type 0xA5, of a GPT `freebsd` partition or of a dedicated disk; offsets relative to the raw
//! partition `c`), OpenBSD's and NetBSD's disklabel (sector 1 of an MBR partition of type 0xA6
//! or 0xA9, or of a GPT `openbsd-data` partition; offsets from the start of the disk, 48-bit
//! with OpenBSD's `d_version` 1), the x86 Solaris VTOC (sector 1 of the fdisk partition 0xBF)
//! and the SPARC VTOC (sector 0, big-endian, cylinder-based), as their headers
//! (`sys/disklabel.h`, `sys/dklabel.h`, `sys/vtoc.h`) lay them out. A label must carry its
//! magic numbers and checksum. Its partitions are numbered `100 * slice + n` (`n` = 1 for `a`
//! or slice 0), or just `n` on a disk with no other table.
//!
//! Nothing here trusts the disk: every offset is checked against the image size, counts are
//! capped, and extended-partition chains stop at a revisited EBR.

use nixcavate_fs::{be16, be32, le16, le32, le64, ReadAt, Slice};
use std::collections::HashSet;

/// Why an LVM2 physical volume is not a filesystem; `lvm` reads these.
pub const LVM_REASON: &str = "LVM2 physical volume";

/// Why a RAID member is not a filesystem; `md` reads these.
pub const MD_REASON: &str = "Linux software RAID member";

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
    /// Set when the contents are recognised but are not a filesystem: LUKS (not read), LVM2
    /// physical volumes ([`LVM_REASON`], read through their logical volumes) and RAID members
    /// ([`MD_REASON`], read through their arrays).
    pub unsupported: Option<&'static str>,
    /// What `PARTUUID=` names: the GPT partition GUID, or `<disk signature>-<number>` of an MBR.
    pub partuuid: Option<String>,
    /// The GPT partition name (`PARTLABEL=`).
    pub partlabel: Option<String>,
}

impl Partition {
    /// A partition with no identity but its size, to build the others from.
    fn none(len: u64) -> Partition {
        Partition {
            index: 1,
            start: 0,
            len,
            type_name: String::new(),
            unsupported: None,
            partuuid: None,
            partlabel: None,
        }
    }
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
        expand_labels(image, parts)
    } else if let Some(parts) = disk_label(image) {
        // Before the filesystem check: the first partition of a labelled disk often starts at
        // sector 0, so the disk also looks like that one filesystem.
        parts
    } else if let Some(name) = filesystem_signature(image) {
        vec![Partition { index: 1, start: 0, len: size, type_name: name.into(), ..Partition::none(size) }]
    } else if let Some(parts) = mbr(image) {
        expand_labels(image, parts)
    } else if unsupported_signature(image).is_some() {
        // Named by the loop below.
        vec![Partition { index: 1, start: 0, len: size, type_name: "raw".into(), ..Partition::none(size) }]
    } else {
        Vec::new()
    };
    for part in &mut parts {
        part.unsupported = unsupported_signature(&Slice { inner: image, start: part.start, len: part.len });
    }
    parts
}

/// The filesystem whose superblock signature sits where `reader` starts: `ext4` (any ext2/3/4,
/// magic 0xEF53 at 1080), `xfs` (`XFSB` at 0), `apfs` (`NXSB` at 32), `btrfs` (`_BHRfS_M`
/// at 64 KiB + 64) or `ufs` (UFS1/UFS2, a valid superblock where FreeBSD looks for one).
pub fn filesystem_signature(reader: &dyn ReadAt) -> Option<&'static str> {
    let head = read_vec(reader, 0, 1082.min(reader.size()))?;
    if head.starts_with(b"XFSB") {
        Some("xfs")
    } else if head.get(32..36) == Some(b"NXSB") {
        Some("apfs")
    } else if head.get(1080..1082) == Some(&[0x53, 0xEF]) {
        Some("ext4")
    } else if read_vec(reader, 0x10040, 8).is_some_and(|magic| magic == b"_BHRfS_M") {
        Some("btrfs")
    } else if nixcavate_fs::zfs::probe(reader) {
        Some("zfs")
    } else if nixcavate_fs::ufs::probe(reader) {
        Some("ufs")
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
    // Filesystems with no reader here: F2FS (magic at 1 KiB), NTFS.
    if head.get(1024..1028) == Some(&0xF2F5_2010u32.to_le_bytes()) {
        return Some("F2FS filesystem");
    }
    if head.get(3..11) == Some(b"NTFS    ") {
        return Some("NTFS filesystem");
    }
    if (0..4).any(|sector| head.get(sector * 512..sector * 512 + 32).is_some_and(is_lvm_label)) {
        return Some(LVM_REASON);
    }
    let md = |at: u64| read_vec(reader, at, 4).is_some_and(|m| m == 0xa92b_4efcu32.to_le_bytes());
    // 1.1 at the start, 1.2 at 4 KiB, 1.0 8 KiB from the end (4 KiB aligned), 0.90 in the
    // last 64 KiB-aligned block.
    let ends = [(size >= 8192).then(|| (size - 8192) & !4095), (size >= 65536).then(|| (size & !65535) - 65536)];
    if md(0) || md(4096) || ends.iter().flatten().any(|&at| md(at)) {
        return Some(MD_REASON);
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
        let name: Vec<u16> = entry[56..128.min(entry.len())]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        parts.push(Partition {
            index: slot + 1,
            start,
            len,
            type_name: gpt_type(type_guid),
            partuuid: Some(guid_string(&entry[16..32])),
            partlabel: Some(String::from_utf16_lossy(&name)).filter(|n| !n.is_empty()),
            ..Partition::none(len)
        });
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
        "516e7cba-6ecf-11d6-8ff8-00022d09712b" => "freebsd_zfs",
        // Solaris /usr, which is also Apple's ZFS type and what `zpool create` gives a whole disk.
        "6a898cc3-1dd2-11b2-99a6-080020736631" => "zfs",
        "83bd6b9d-7f41-11dc-be0b-001560b84f0f" => "freebsd_boot",
        "516e7cb4-6ecf-11d6-8ff8-00022d09712b" => "freebsd",
        "516e7cb5-6ecf-11d6-8ff8-00022d09712b" => "freebsd_swap",
        "516e7cb6-6ecf-11d6-8ff8-00022d09712b" => "freebsd_ufs",
        "516e7cb8-6ecf-11d6-8ff8-00022d09712b" => "freebsd_vinum",
        "49f48d32-b10e-11dc-b99b-0019d1879648" => "netbsd_swap",
        "49f48d5a-b10e-11dc-b99b-0019d1879648" => "netbsd_ffs",
        "49f48d82-b10e-11dc-b99b-0019d1879648" => "netbsd_lfs",
        "49f48daa-b10e-11dc-b99b-0019d1879648" => "netbsd_raid",
        "2db519c4-b10f-11dc-b99b-0019d1879648" => "netbsd_concatenated",
        "2db519ec-b10f-11dc-b99b-0019d1879648" => "netbsd_encrypted",
        "824cc7a0-36a8-11e3-890a-952519ad3f61" => "openbsd_data",
        "6a82cb45-1dd2-11b2-99a6-080020736631" => "solaris_boot",
        "6a85cf4d-1dd2-11b2-99a6-080020736631" => "solaris_root",
        "6a87c46f-1dd2-11b2-99a6-080020736631" => "solaris_swap",
        "6a8b642b-1dd2-11b2-99a6-080020736631" => "solaris_backup",
        "6a8ef2e9-1dd2-11b2-99a6-080020736631" => "solaris_var",
        "6a90ba39-1dd2-11b2-99a6-080020736631" => "solaris_home",
        "6a9283a5-1dd2-11b2-99a6-080020736631" => "solaris_alternate_sector",
        "6a945a3b-1dd2-11b2-99a6-080020736631"
        | "6a9630d1-1dd2-11b2-99a6-080020736631"
        | "6a980767-1dd2-11b2-99a6-080020736631"
        | "6a96237f-1dd2-11b2-99a6-080020736631"
        | "6a8d2ac7-1dd2-11b2-99a6-080020736631" => "solaris_reserved",
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
        0xa5 => "freebsd",
        0xa6 => "openbsd",
        0xa9 => "netbsd",
        0xbf => "solaris",
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
    let signature = le32(&read_vec(image, 0, 512)?, 440);
    let make = |index: usize, start: u64, count: u32, id: u8| Partition {
        index,
        start: start * SECTOR,
        len: (count as u64 * SECTOR).min(size - start * SECTOR),
        type_name: mbr_type(id),
        partuuid: Some(format!("{signature:08x}-{index:02x}")),
        ..Partition::none(0)
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

/// The system whose label a slice of this type holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    FreeBsd,
    OpenBsd,
    NetBsd,
    Solaris,
}

const DISKLABEL_MAGIC: u32 = 0x8256_4557;
/// Partitions a label in one 512-byte sector can hold (148-byte header, 16 bytes each).
const MAX_LABEL_PARTITIONS: usize = 22;
const VTOC_MAGIC: u16 = 0xDABE;
const VTOC_SANITY: u32 = 0x600D_DEEE;
/// A Solaris VTOC tag for the slice that covers the whole disk.
const VTOC_BACKUP: u16 = 5;

/// Replaces each slice that holds a BSD disklabel or a Solaris VTOC with the partitions in it.
fn expand_labels(image: &dyn ReadAt, parts: Vec<Partition>) -> Vec<Partition> {
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        let kind = match part.type_name.as_str() {
            "freebsd" => Some(Label::FreeBsd),
            "openbsd" | "openbsd_data" => Some(Label::OpenBsd),
            "netbsd" => Some(Label::NetBsd),
            "solaris" => Some(Label::Solaris),
            _ => None,
        };
        let slice = Slice { inner: image, start: part.start, len: part.len };
        let found = match kind {
            Some(Label::Solaris) => vtoc_x86(&slice),
            Some(kind) => bsd_label(&slice, kind, part.start / 512, image.size().saturating_sub(part.start)),
            None => None,
        };
        match found {
            Some(subs) if !subs.is_empty() => {
                out.extend(subs.into_iter().map(|(n, start, len, type_name)| Partition {
                    index: part.index * 100 + n,
                    start: part.start + start,
                    len,
                    type_name,
                    ..Partition::none(len)
                }))
            }
            _ => out.push(part),
        }
    }
    out
}

/// A label that covers the whole disk: a SPARC VTOC in sector 0, or a BSD disklabel in
/// sector 1 of a disk with no partition table of its own (or the MBR of a "dedicated" one).
fn disk_label(image: &dyn ReadAt) -> Option<Vec<Partition>> {
    let subs = vtoc_sparc(image).or_else(|| bsd_label(image, Label::FreeBsd, 0, image.size()))?;
    let parts: Vec<Partition> = subs
        .into_iter()
        .map(|(index, start, len, type_name)| Partition { index, start, len, type_name, ..Partition::none(len) })
        .collect();
    (!parts.is_empty()).then_some(parts)
}

/// XOR of the 16-bit words of `data`, which a label's checksum makes zero.
fn xor16(data: &[u8], big: bool) -> u16 {
    data.chunks_exact(2)
        .map(|w| if big { u16::from_be_bytes([w[0], w[1]]) } else { u16::from_le_bytes([w[0], w[1]]) })
        .fold(0, |a, w| a ^ w)
}

/// Clips a partition of `start` and `count` sectors of `sector` bytes to a slice of `len`
/// bytes: `None` when it is empty or starts past the end.
fn clip(start: u64, count: u64, sector: u64, len: u64) -> Option<(u64, u64)> {
    let start = start.checked_mul(sector)?;
    let end = count.checked_mul(sector)?.checked_add(start)?.min(len);
    (start < end).then(|| (start, end - start))
}

/// The partitions of a BSD disklabel in sector 1 of `slice`, which starts `first` sectors into
/// the disk and `disk_left` bytes before its end: (number, byte offset in the slice, length,
/// type name).
fn bsd_label(slice: &dyn ReadAt, kind: Label, first: u64, disk_left: u64) -> Option<Vec<(usize, u64, u64, String)>> {
    let sector = read_vec(slice, 512, 512)?;
    let big = if le32(&sector, 0) == DISKLABEL_MAGIC && le32(&sector, 132) == DISKLABEL_MAGIC {
        false
    } else if be32(&sector, 0) == DISKLABEL_MAGIC && be32(&sector, 132) == DISKLABEL_MAGIC {
        true
    } else {
        return None;
    };
    let u16_at = |at: usize| if big { be16(&sector, at) } else { le16(&sector, at) };
    let u32_at = |at: usize| u64::from(if big { be32(&sector, at) } else { le32(&sector, at) });
    let count = usize::from(u16_at(138));
    if count == 0 || count > MAX_LABEL_PARTITIONS || xor16(&sector[..148 + 16 * count], big) != 0 {
        return None;
    }
    let secsize = match u32_at(40) {
        s @ (512 | 1024 | 2048 | 4096) => s,
        _ => 512,
    };
    // OpenBSD's version 1 labels keep the high 16 bits of offsets and sizes where FreeBSD
    // keeps the fragment size.
    let wide = u16_at(114) == 1;
    let kind = if wide { Label::OpenBsd } else { kind };
    let entry = |i: usize| {
        let at = 148 + 16 * i;
        let (mut size, mut offset) = (u32_at(at), u32_at(at + 4));
        if wide {
            offset |= u64::from(u16_at(at + 8)) << 32;
            size |= u64::from(u16_at(at + 10)) << 32;
        }
        (size, offset, sector[at + 12])
    };
    // FreeBSD counts from where its raw partition `c` starts (the slice, or 0 when the
    // offsets are already relative); OpenBSD and NetBSD from the start of the disk.
    let base = match kind {
        Label::FreeBsd if count > 2 => entry(2).1,
        Label::FreeBsd => 0,
        _ => first.saturating_mul(512) / secsize,
    };
    let os = match kind {
        Label::FreeBsd => "freebsd",
        Label::OpenBsd => "openbsd",
        Label::NetBsd => "netbsd",
        Label::Solaris => "solaris",
    };
    // OpenBSD and NetBSD count from the disk, and resize a filesystem by rewriting the label
    // alone: a partition may reach past the MBR entry the label is in, up to the end of the disk.
    let bound = if matches!(kind, Label::FreeBsd) { slice.size() } else { disk_left.max(slice.size()) };
    let mut out = Vec::new();
    for i in 0..count {
        let (size, offset, fstype) = entry(i);
        if fstype == 0 || size == 0 {
            continue;
        }
        let Some((start, len)) = offset.checked_sub(base).and_then(|o| clip(o, size, secsize, bound)) else {
            continue;
        };
        let type_name = match (fstype, kind) {
            (1, _) => format!("{os}_swap"),
            (7, Label::FreeBsd) => "freebsd_ufs".into(),
            (7, _) => format!("{os}_ffs"),
            (14, Label::FreeBsd) => "freebsd_vinum".into(),
            (27, Label::FreeBsd) => "freebsd_zfs".into(),
            (t, _) => format!("{os}_fstype_{t}"),
        };
        out.push((i + 1, start, len, type_name));
    }
    Some(out)
}

/// The name of a Solaris VTOC tag.
fn vtoc_tag(tag: u16) -> String {
    let name = match tag {
        1 => "boot",
        2 => "root",
        3 => "swap",
        4 => "usr",
        6 => "stand",
        7 => "var",
        8 => "home",
        9 => "alternate_sector",
        11 => "reserved",
        _ => return format!("solaris_tag_{tag}"),
    };
    format!("solaris_{name}")
}

/// The slices of an x86 Solaris VTOC in sector 1 of an fdisk partition: little-endian, 16
/// slices with tag, start sector (from the partition's start) and size.
fn vtoc_x86(slice: &dyn ReadAt) -> Option<Vec<(usize, u64, u64, String)>> {
    let label = read_vec(slice, 512, 512)?;
    if le16(&label, 508) != VTOC_MAGIC || xor16(&label, false) != 0 || le32(&label, 12) != VTOC_SANITY {
        return None;
    }
    let count = usize::from(le16(&label, 30)).min(16);
    let mut out = Vec::new();
    for i in 0..count {
        let at = 72 + 12 * i;
        let tag = le16(&label, at);
        if tag == VTOC_BACKUP {
            continue;
        }
        if let Some((start, len)) =
            clip(u64::from(le32(&label, at + 4)), u64::from(le32(&label, at + 8)), 512, slice.size())
        {
            out.push((i + 1, start, len, vtoc_tag(tag)));
        }
    }
    Some(out)
}

/// The slices of a SPARC VTOC in sector 0: big-endian, 8 slices given as a starting cylinder
/// and a size, with tags when the VTOC part of the label is present (Solaris); without it (a
/// plain Sun label, as NetBSD and OpenBSD write) each slice is named `sun`.
fn vtoc_sparc(disk: &dyn ReadAt) -> Option<Vec<(usize, u64, u64, String)>> {
    let label = read_vec(disk, 0, 512)?;
    if be16(&label, 508) != VTOC_MAGIC || xor16(&label, true) != 0 {
        return None;
    }
    let vtoc = be32(&label, 188) == VTOC_SANITY;
    let per_cylinder = u64::from(be16(&label, 436)) * u64::from(be16(&label, 438));
    if per_cylinder == 0 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..8 {
        let tag = if vtoc { be16(&label, 142 + 4 * i) } else { 0 };
        // Without a VTOC, slice 2 is the whole disk by convention.
        if tag == VTOC_BACKUP || (!vtoc && i == 2) {
            continue;
        }
        let at = 444 + 8 * i;
        let first = u64::from(be32(&label, at)).checked_mul(per_cylinder)?;
        let Some((start, len)) = clip(first, u64::from(be32(&label, at + 4)), 512, disk.size()) else { continue };
        // NetBSD and OpenBSD labels repeat the whole disk in more than one slice.
        if out.iter().any(|&(_, s, l, _)| (s, l) == (start, len)) {
            continue;
        }
        out.push((i + 1, start, len, if vtoc { vtoc_tag(tag) } else { "sun".into() }));
    }
    Some(out)
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

        let mut btrfs = vec![0u8; 0x11000];
        btrfs[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
        let parts = scan(&Bytes(&btrfs));
        assert_eq!((parts[0].type_name.as_str(), parts[0].unsupported), ("btrfs", None));

        // A ZFS vdev label: an XDR name-value list at 16 KiB and an uberblock at 128 KiB.
        let mut zfs = vec![0u8; 0x40000];
        zfs[0x4000..0x400c].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        zfs[0x20000..0x20008].copy_from_slice(&0x00ba_b10cu64.to_le_bytes());
        assert_eq!(scan(&Bytes(&zfs))[0].type_name, "zfs");
        zfs[0x20000..0x20008].fill(0);
        assert!(scan(&Bytes(&zfs)).is_empty());

        assert!(scan(&Bytes(&[0u8; 4096])).is_empty());
        assert!(scan(&Bytes(&[])).is_empty());
    }

    #[test]
    fn filesystems_that_are_not_read_are_named() {
        let mut f2fs = vec![0u8; 8192];
        f2fs[1024..1028].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
        assert_eq!(scan(&Bytes(&f2fs))[0].unsupported, Some("F2FS filesystem"));
        let mut ntfs = vec![0u8; 8192];
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(scan(&Bytes(&ntfs))[0].unsupported, Some("NTFS filesystem"));
        // ext4 has its own magic at 1080 and is not confused with any of them.
        let mut ext = vec![0u8; 8192];
        ext[1080..1082].copy_from_slice(&[0x53, 0xef]);
        assert_eq!(scan(&Bytes(&ext))[0].unsupported, None);
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

    fn ufs_fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs/ufs").join(name);
        zstd::decode_all(std::fs::File::open(path).unwrap()).unwrap()
    }

    /// FreeBSD's `gpart`: an MBR with two 0xA5 slices, the first split by a bsdlabel into
    /// a (UFS), b (swap) and d (UFS); the second has no label and stays whole.
    #[test]
    fn freebsd_bsdlabel_in_an_mbr_slice() {
        let disk = ufs_fixture("mbr-bsdlabel.img.zst");
        let parts = scan(&Bytes(&disk));
        let s1 = 512;
        assert_eq!(
            summary(&parts),
            [
                (101, s1, 16 * MIB, "freebsd_ufs"),
                (102, s1 + 16 * MIB, 8 * MIB, "freebsd_swap"),
                (104, s1 + 24 * MIB, 16 * MIB, "freebsd_ufs"),
                (2, 98305 * 512, 8 * MIB, "freebsd"),
            ]
        );
        for part in [&parts[0], &parts[2]] {
            let slice = Slice { inner: Bytes(&disk), start: part.start, len: part.len };
            assert_eq!(filesystem_signature(&slice), Some("ufs"), "{part:?}");
        }
    }

    #[test]
    fn freebsd_gpt_types() {
        let parts = scan(&Bytes(&ufs_fixture("gpt-freebsd.img.zst")));
        let names: Vec<&str> = parts.iter().map(|p| p.type_name.as_str()).collect();
        assert_eq!(names, ["freebsd_boot", "freebsd_ufs", "freebsd_swap", "freebsd_ufs"]);
    }

    /// A disklabel sector: `parts` are (size, offset, fstype) in sectors; `wide` writes
    /// OpenBSD's version 1 with the high offset bits in `high`.
    fn disklabel(big: bool, parts: &[(u32, u32, u8)], wide: Option<u16>) -> Vec<u8> {
        let mut l = vec![0u8; 512];
        let put32 = |l: &mut Vec<u8>, at: usize, v: u32| {
            l[at..at + 4].copy_from_slice(&if big { v.to_be_bytes() } else { v.to_le_bytes() })
        };
        let put16 = |l: &mut Vec<u8>, at: usize, v: u16| {
            l[at..at + 2].copy_from_slice(&if big { v.to_be_bytes() } else { v.to_le_bytes() })
        };
        put32(&mut l, 0, DISKLABEL_MAGIC);
        put32(&mut l, 132, DISKLABEL_MAGIC);
        put32(&mut l, 40, 512);
        put16(&mut l, 138, parts.len() as u16);
        for (i, &(size, offset, fstype)) in parts.iter().enumerate() {
            let at = 148 + 16 * i;
            put32(&mut l, at, size);
            put32(&mut l, at + 4, offset);
            l[at + 12] = fstype;
            if let Some(high) = wide {
                put16(&mut l, at + 8, high);
            }
        }
        if wide.is_some() {
            put16(&mut l, 114, 1);
        }
        let sum = xor16(&l[..148 + 16 * parts.len()], big);
        put16(&mut l, 136, sum);
        l
    }

    /// A disk with one MBR partition of type `id` at sector 2048 holding `label` in its sector 1.
    fn mbr_with_label(id: u8, label: &[u8]) -> Vec<u8> {
        let mut disk = vec![0u8; 8 << 20];
        disk[446 + 4] = id;
        disk[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&14336u32.to_le_bytes());
        disk[510..512].copy_from_slice(&[0x55, 0xaa]);
        disk[2049 * 512..2050 * 512].copy_from_slice(label);
        disk
    }

    #[test]
    fn openbsd_and_netbsd_labels_count_from_the_disk() {
        // a at 4096 (absolute), b swap, c the whole disk (unused type).
        let parts = [(4096, 4096, 7), (2048, 8192, 1), (16384, 0, 0)];
        let disk = mbr_with_label(0xa6, &disklabel(false, &parts, None));
        assert_eq!(
            summary(&scan(&Bytes(&disk))),
            [(101, 4096 * 512, 2 * MIB, "openbsd_ffs"), (102, 8192 * 512, MIB, "openbsd_swap")]
        );
        let disk = mbr_with_label(0xa9, &disklabel(false, &parts, None));
        assert_eq!(summary(&scan(&Bytes(&disk)))[0], (101, 4096 * 512, 2 * MIB, "netbsd_ffs"));
        // OpenBSD version 1: high 16 bits of offsets past the 8 MiB disk drop the partition.
        let disk = mbr_with_label(0xa6, &disklabel(false, &parts, Some(1)));
        assert!(scan(&Bytes(&disk)).iter().all(|p| p.index != 101));
    }

    /// NetBSD grows a filesystem by rewriting its disklabel; the MBR entry around it keeps the
    /// old size. The label counts from the disk, so it is bounded by the disk.
    #[test]
    fn a_netbsd_label_may_reach_past_its_mbr_partition() {
        let mut disk = mbr_with_label(0xa9, &disklabel(false, &[(28672, 2048, 7), (0, 0, 0), (28672, 2048, 0)], None));
        disk.resize(16 << 20, 0);
        assert_eq!(summary(&scan(&Bytes(&disk))), [(101, 2048 * 512, 14 * MIB, "netbsd_ffs")]);
        // Still cut at the end of the disk.
        disk.truncate(12 << 20);
        assert_eq!(summary(&scan(&Bytes(&disk))), [(101, 2048 * 512, 11 * MIB, "netbsd_ffs")]);
    }

    #[test]
    fn a_label_with_a_bad_checksum_is_not_a_label() {
        let mut label = disklabel(false, &[(4096, 2048, 7), (2048, 0, 0), (14336, 2048, 0)], None);
        label[150] ^= 1;
        let disk = mbr_with_label(0xa5, &label);
        assert_eq!(summary(&scan(&Bytes(&disk))), [(1, 2048 * 512, 7 * MIB, "freebsd")]);
    }

    /// A dedicated disk: no table but a bsdlabel in sector 1, `a` starting at sector 0.
    #[test]
    fn a_disk_with_only_a_bsdlabel() {
        let mut disk = vec![0u8; 8 << 20];
        disk[512..1024].copy_from_slice(&disklabel(true, &[(8192, 0, 7), (4096, 8192, 1), (16384, 0, 0)], None));
        assert_eq!(
            summary(&scan(&Bytes(&disk))),
            [(1, 0, 4 * MIB, "freebsd_ufs"), (2, 4 * MIB, 2 * MIB, "freebsd_swap")]
        );
    }

    fn vtoc_checksum(label: &mut [u8], big: bool) {
        label[510..512].fill(0);
        let sum = xor16(label, big);
        label[510..512].copy_from_slice(&if big { sum.to_be_bytes() } else { sum.to_le_bytes() });
    }

    /// illumos's `fdisk -B` and `fmthard` (OmniOS): a Solaris2 fdisk partition at sector 2048
    /// whose VTOC has root (slice 0), swap (1), backup (2) and home (7); UFS on 0 and 7.
    #[test]
    fn solaris_vtoc_written_by_illumos() {
        let disk = ufs_fixture("solaris-vtoc.img.zst");
        let parts = scan(&Bytes(&disk));
        let base = 2048 * 512;
        assert_eq!(
            summary(&parts),
            [
                (101, base + 4096 * 512, 16 * MIB, "solaris_root"),
                (102, base + 36864 * 512, 8 * MIB, "solaris_swap"),
                (108, base + 53248 * 512, 20 * MIB, "solaris_home"),
            ]
        );
        for part in [&parts[0], &parts[2]] {
            let slice = Slice { inner: Bytes(&disk), start: part.start, len: part.len };
            assert_eq!(filesystem_signature(&slice), Some("ufs"), "{part:?}");
        }
    }

    #[test]
    fn solaris_x86_vtoc() {
        let mut label = vec![0u8; 512];
        label[12..16].copy_from_slice(&VTOC_SANITY.to_le_bytes());
        label[30..32].copy_from_slice(&16u16.to_le_bytes());
        // Slice 0 root at 1024, slice 1 swap, slice 2 backup (whole), slice 7 home.
        for (i, tag, start, size) in
            [(0usize, 2u16, 1024u32, 4096u32), (1, 3, 5120, 2048), (2, 5, 0, 14336), (7, 8, 7168, 4096)]
        {
            let at = 72 + 12 * i;
            label[at..at + 2].copy_from_slice(&tag.to_le_bytes());
            label[at + 4..at + 8].copy_from_slice(&start.to_le_bytes());
            label[at + 8..at + 12].copy_from_slice(&size.to_le_bytes());
        }
        label[508..510].copy_from_slice(&VTOC_MAGIC.to_le_bytes());
        vtoc_checksum(&mut label, false);
        let disk = mbr_with_label(0xbf, &label);
        let base = 2048 * 512;
        assert_eq!(
            summary(&scan(&Bytes(&disk))),
            [
                (101, base + 512 * 1024, 2 * MIB, "solaris_root"),
                (102, base + 512 * 5120, MIB, "solaris_swap"),
                (108, base + 512 * 7168, 2 * MIB, "solaris_home"),
            ]
        );
    }

    #[test]
    fn sparc_vtoc() {
        let mut disk = vec![0u8; 8 << 20];
        let label = &mut disk[..512];
        label[188..192].copy_from_slice(&VTOC_SANITY.to_be_bytes());
        label[436..438].copy_from_slice(&16u16.to_be_bytes()); // heads
        label[438..440].copy_from_slice(&32u16.to_be_bytes()); // sectors: 512 per cylinder
        for (i, tag, cyl, size) in [(0usize, 2u16, 0u32, 4096u32), (2, 5, 0, 16384), (6, 4, 8, 4096)] {
            label[142 + 4 * i..144 + 4 * i].copy_from_slice(&tag.to_be_bytes());
            label[444 + 8 * i..448 + 8 * i].copy_from_slice(&cyl.to_be_bytes());
            label[448 + 8 * i..452 + 8 * i].copy_from_slice(&size.to_be_bytes());
        }
        label[508..510].copy_from_slice(&VTOC_MAGIC.to_be_bytes());
        vtoc_checksum(label, true);
        // Slice 0 starts at sector 0 and holds a UFS, but the label wins over the bare filesystem.
        disk[8192 + 1372..8192 + 1376].copy_from_slice(&0x0001_1954u32.to_be_bytes());
        assert_eq!(
            summary(&scan(&Bytes(&disk))),
            [(1, 0, 2 * MIB, "solaris_root"), (7, 8 * 512 * 512, 2 * MIB, "solaris_usr")]
        );
        // A plain Sun label (no VTOC part, as NetBSD and OpenBSD write it): slice 2 is the disk.
        disk[188..192].fill(0);
        vtoc_checksum(&mut disk[..512], true);
        assert_eq!(summary(&scan(&Bytes(&disk))), [(1, 0, 2 * MIB, "sun"), (7, 8 * 512 * 512, 2 * MIB, "sun")]);
    }

    #[test]
    fn hostile_labels_do_not_panic() {
        let parts = [(4096, 4096, 7), (2048, 8192, 1), (16384, 0, 0)];
        for (id, big) in [(0xa5u8, false), (0xa6, false), (0xa9, true)] {
            let base = mbr_with_label(id, &disklabel(big, &parts, Some(0)));
            for at in (2049 * 512..2050 * 512).step_by(3) {
                for v in [0u8, 1, 0x7f, 0x80, 0xff] {
                    let mut disk = base.clone();
                    disk[at] = v;
                    for part in scan(&Bytes(&disk)) {
                        assert!(part.start + part.len <= disk.len() as u64);
                    }
                }
            }
        }
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

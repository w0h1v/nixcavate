//! Microsoft VHDX reader, written from [MS-VHDX] "Virtual Hard Disk v2 (VHDX) File Format".
//!
//! All fields are little endian; GUIDs are stored mixed-endian. Layout:
//!
//! * 64 KiB file type identifier (`vhdxfile`), then two 4 KiB headers at 64 KiB and 128 KiB
//!   (`head`; sequence number, log GUID; CRC-32C of the 4 KiB with the checksum field zeroed).
//!   The valid header with the higher sequence number is current.
//! * Two region tables at 192 KiB and 256 KiB (`regi`; CRC-32C over 64 KiB) naming the block
//!   allocation table (BAT) and the metadata region; an unknown region marked required is a
//!   refusal.
//! * The metadata table (`metadata`) locates the file parameters (block size, has-parent flag),
//!   the virtual disk size and the logical sector size.
//! * The BAT holds one u64 per payload block, with a sector bitmap entry after every
//!   `chunk ratio` payload blocks. Bits 0 to 2 are the state, bits 20 to 63 the block's file
//!   offset in MiB. NOT_PRESENT, UNDEFINED, ZERO and UNMAPPED read as zeros; FULLY_PRESENT is
//!   data; PARTIALLY_PRESENT exists only in differencing disks.
//!
//! A non-zero log GUID in the current header means the disk was not closed cleanly and its log
//! may hold writes that never reached their place. The log is not replayed (a replay done
//! wrong would be silently wrong data): the disk is read without it, with one warning.
//! Differencing disks (has-parent) are refused.

use super::vdisk::{bad, crc32c, for_blocks, refuse, slice, Data, Disk};
use nixcavate_fs::{le16, le32, le64, ReadAt};
use std::io;
use std::sync::Arc;

const NAME: &str = "VHDX";
const KIB: u64 = 1024;
const MIB: u64 = 1 << 20;
const HEADERS: [u64; 2] = [64 * KIB, 128 * KIB];
const REGION_TABLES: [u64; 2] = [192 * KIB, 256 * KIB];
const HEADER_LEN: usize = 4096;
const REGION_TABLE_LEN: usize = 64 * 1024;
const MAX_ENTRIES: usize = 2047;
const BLOCK_RANGE: std::ops::RangeInclusive<u32> = 1 << 20..=256 << 20;

/// A GUID as stored on disk, from its canonical text.
const fn guid(text: &str) -> [u8; 16] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let text = text.as_bytes();
    let (mut hex, mut n, mut i) = ([0u8; 16], 0, 0);
    while i < text.len() {
        if text[i] != b'-' {
            if n % 2 == 0 {
                hex[n / 2] = nibble(text[i]) << 4;
            } else {
                hex[n / 2] |= nibble(text[i]);
            }
            n += 1;
        }
        i += 1;
    }
    [
        hex[3], hex[2], hex[1], hex[0], hex[5], hex[4], hex[7], hex[6], hex[8], hex[9], hex[10], hex[11], hex[12],
        hex[13], hex[14], hex[15],
    ]
}

const REGION_BAT: [u8; 16] = guid("2DC27766-F623-4200-9D64-115E9BFD4A08");
const REGION_METADATA: [u8; 16] = guid("8B7CA206-4790-4B9A-B8FE-575F050F886E");
const ITEM_FILE_PARAMETERS: [u8; 16] = guid("CAA16737-FA36-4D43-B3B6-33F0AA44E76B");
const ITEM_DISK_SIZE: [u8; 16] = guid("2FA54224-CD1B-4876-B211-5DBED83BF4B8");
const ITEM_DISK_ID: [u8; 16] = guid("BECA12AB-B2E6-4523-93EF-C309E000C746");
const ITEM_LOGICAL_SECTOR: [u8; 16] = guid("8141BF1D-A96F-4709-BA47-F233A8FAAB5F");
const ITEM_PHYSICAL_SECTOR: [u8; 16] = guid("CDA348C7-445D-4471-9CC9-E9885251C556");
const ITEM_PARENT_LOCATOR: [u8; 16] = guid("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C");

const STATE_FULLY_PRESENT: u64 = 6;
const STATE_PARTIALLY_PRESENT: u64 = 7;

pub struct Vhdx {
    file: Data,
    size: u64,
    block_size: u64,
    /// Payload blocks per sector bitmap block.
    chunk_ratio: u64,
    bat: u64,
}

/// The CRC-32C of `data` with its checksum field (4 bytes at `field`) taken as zeros.
fn checksum_ok(data: &[u8], field: usize) -> bool {
    let mut copy = data.to_vec();
    if let Some(f) = copy.get_mut(field..field + 4) {
        f.fill(0);
    }
    crc32c(&copy) == le32(data, field)
}

pub fn open(file: Data) -> io::Result<Disk> {
    let bytes: &[u8] = (*file).as_ref();
    if (bytes.len() as u64) < REGION_TABLES[1] + REGION_TABLE_LEN as u64 {
        return Err(bad(NAME, "the file is too short for its headers"));
    }
    // The current header: valid, highest sequence number.
    let current = HEADERS
        .iter()
        .filter_map(|&at| slice(bytes, at, HEADER_LEN))
        .filter(|h| h.starts_with(b"head") && checksum_ok(h, 4))
        .max_by_key(|h| le64(h, 8))
        .ok_or_else(|| bad(NAME, "no valid header (both fail their checksum)"))?;
    if le16(current, 66) != 1 {
        return Err(refuse(NAME, format!("version {} is not supported", le16(current, 66))));
    }
    if le16(current, 64) != 0 {
        return Err(refuse(NAME, format!("log version {} is not supported", le16(current, 64))));
    }
    let mut notes = Vec::new();
    let dirty = current.get(48..64).is_some_and(|g| g.iter().any(|&b| b != 0));

    // The first region table that checks out.
    let table = REGION_TABLES
        .iter()
        .filter_map(|&at| slice(bytes, at, REGION_TABLE_LEN))
        .find(|t| t.starts_with(b"regi") && checksum_ok(t, 4))
        .ok_or_else(|| bad(NAME, "no valid region table (both fail their checksum)"))?;
    let count = le32(table, 8) as usize;
    if count > MAX_ENTRIES {
        return Err(bad(NAME, "implausible region count"));
    }
    let (mut bat, mut metadata) = (None, None);
    for i in 0..count {
        let entry = table.get(16 + i * 32..16 + i * 32 + 32).ok_or_else(|| bad(NAME, "region table is cut off"))?;
        let id = &entry[..16];
        let (offset, length) = (le64(entry, 16), u64::from(le32(entry, 24)));
        let required = le32(entry, 28) & 1 != 0;
        let region = if id == REGION_BAT {
            &mut bat
        } else if id == REGION_METADATA {
            &mut metadata
        } else if required {
            return Err(refuse(NAME, "the disk needs a region this reader does not know"));
        } else {
            continue;
        };
        if offset < MIB || offset % MIB != 0 || offset.checked_add(length).is_none_or(|end| end > bytes.len() as u64) {
            return Err(bad(NAME, "a region lies outside the file"));
        }
        *region = Some((offset, length));
    }
    let (bat_at, bat_len) = bat.ok_or_else(|| bad(NAME, "no block allocation table region"))?;
    let (meta_at, meta_len) = metadata.ok_or_else(|| bad(NAME, "no metadata region"))?;

    let meta = slice(bytes, meta_at, usize::try_from(meta_len).map_err(|_| bad(NAME, "metadata size"))?)
        .filter(|m| m.starts_with(b"metadata"))
        .ok_or_else(|| bad(NAME, "the metadata table is missing"))?;
    let items = usize::from(le16(meta, 10));
    if items > MAX_ENTRIES {
        return Err(bad(NAME, "implausible metadata item count"));
    }
    let (mut params, mut size, mut sector) = (None, None, None);
    for i in 0..items {
        let entry = meta.get(32 + i * 32..32 + i * 32 + 32).ok_or_else(|| bad(NAME, "metadata table is cut off"))?;
        let id = &entry[..16];
        let (offset, length, flags) = (le32(entry, 16) as usize, le32(entry, 20) as usize, le32(entry, 24));
        let value = || meta.get(offset..offset.checked_add(length)?);
        if id == ITEM_FILE_PARAMETERS {
            params = value();
        } else if id == ITEM_DISK_SIZE {
            size = value();
        } else if id == ITEM_LOGICAL_SECTOR {
            sector = value();
        } else if id == ITEM_PARENT_LOCATOR {
            return Err(refuse(NAME, "the disk is a differencing disk (it has a parent); consolidate the chain first"));
        } else if id != ITEM_DISK_ID && id != ITEM_PHYSICAL_SECTOR && flags & 4 != 0 {
            return Err(refuse(NAME, "the disk needs a metadata item this reader does not know"));
        }
    }
    let params = params.filter(|p| p.len() >= 8).ok_or_else(|| bad(NAME, "no file parameters"))?;
    let (block_size, parameter_flags) = (le32(params, 0), le32(params, 4));
    if parameter_flags & 2 != 0 {
        return Err(refuse(NAME, "the disk is a differencing disk (it has a parent); consolidate the chain first"));
    }
    if !BLOCK_RANGE.contains(&block_size) || !block_size.is_power_of_two() {
        return Err(bad(NAME, format!("implausible block size {block_size}")));
    }
    let block_size = u64::from(block_size);
    let size = size.filter(|s| s.len() >= 8).map(|s| le64(s, 0)).filter(|&s| s <= i64::MAX as u64);
    let size = size.ok_or_else(|| bad(NAME, "no usable virtual disk size"))?;
    let sector = sector.filter(|s| s.len() >= 4).map(|s| le32(s, 0));
    let sector = match sector {
        Some(s @ (512 | 4096)) => u64::from(s),
        _ => return Err(bad(NAME, "no usable logical sector size")),
    };
    let chunk_ratio = ((1u64 << 23) * sector / block_size).max(1);
    let payload = size.div_ceil(block_size);
    let entries = if payload == 0 { 0 } else { payload + (payload - 1) / chunk_ratio };
    if entries.checked_mul(8).is_none_or(|b| b > bat_len) {
        return Err(bad(NAME, format!("the block allocation table is too small for {entries} entries")));
    }
    if dirty {
        notes.push(format!(
            "{NAME}: the disk was not closed cleanly (its log is not empty) and the log is not replayed; recent writes may be missing"
        ));
    }
    notes.insert(0, format!("VHDX virtual disk read directly: {size} bytes, {} MiB blocks", block_size >> 20));
    Ok(Disk { reader: Arc::new(Vhdx { file, size, block_size, chunk_ratio, bat: bat_at }), notes })
}

impl ReadAt for Vhdx {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let bytes: &[u8] = (*self.file).as_ref();
        for_blocks(self.size, self.block_size, offset, buf, |start, within, out| {
            let block = start / self.block_size;
            let index = block + block / self.chunk_ratio;
            let entry = slice(bytes, self.bat + index * 8, 8)
                .ok_or_else(|| bad(NAME, "the block allocation table is cut off"))?;
            let entry = le64(entry, 0);
            match entry & 7 {
                0..=3 => out.fill(0),
                STATE_FULLY_PRESENT => {
                    let at = (entry >> 20) * MIB;
                    let src = at
                        .checked_add(within as u64)
                        .filter(|_| at >= MIB)
                        .and_then(|from| slice(bytes, from, out.len()))
                        .ok_or_else(|| bad(NAME, format!("block {block} lies outside the file")))?;
                    out.copy_from_slice(src);
                }
                STATE_PARTIALLY_PRESENT => {
                    return Err(bad(
                        NAME,
                        format!("block {block} is partially present, which only a differencing disk uses"),
                    ));
                }
                state => return Err(bad(NAME, format!("block {block} has the unknown state {state}"))),
            }
            Ok(())
        })
    }

    fn size(&self) -> u64 {
        self.size
    }
}

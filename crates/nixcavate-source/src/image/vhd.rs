//! Microsoft VHD reader, written from "Virtual Hard Disk Image Format Specification" (2006).
//!
//! All fields are big endian. Every VHD ends with a 512-byte footer (`conectix`): disk type,
//! the virtual size and a checksum (the one's complement of the byte sum, checksum field
//! zeroed).
//!
//! * Fixed: the file is the disk followed by the footer, so the disk is the file minus its last
//!   512 bytes. Nothing marks such a file at its start, hence [`open_fixed`] looks at the end.
//! * Dynamic: the footer is repeated at offset 0, followed by a 1024-byte dynamic header
//!   (`cxsparse`; block allocation table offset, number of entries, block size, checksum). The
//!   table holds one u32 sector number per block (`0xFFFFFFFF` is unallocated and reads as
//!   zeros). A block is a sector bitmap (one bit per sector, most significant bit first, rounded
//!   up to 512 bytes) followed by the data; a sector whose bit is clear reads as zeros.
//! * Differencing disks need their parent and are refused, naming it.

use super::vdisk::{bad, for_blocks, refuse, slice, Data, Disk};
use nixcavate_fs::{be32, be64, ReadAt};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

const NAME: &str = "VHD";
const FOOTER: usize = 512;
const DYNAMIC_HEADER: usize = 1024;
const TYPE_FIXED: u32 = 2;
const TYPE_DYNAMIC: u32 = 3;
const TYPE_DIFFERENCING: u32 = 4;
const UNALLOCATED: u32 = 0xFFFF_FFFF;
/// Block sizes accepted: 512 bytes to 1 GiB (Virtual PC and Hyper-V use 512 KiB or 2 MiB).
const BLOCK_RANGE: std::ops::RangeInclusive<u32> = 512..=1 << 30;

/// The footer's checksum is the one's complement of the sum of the other bytes.
fn checksum(data: &[u8], field: usize) -> u32 {
    let sum = data
        .iter()
        .enumerate()
        .filter(|(i, _)| !(field..field + 4).contains(i))
        .fold(0u32, |s, (_, &b)| s.wrapping_add(u32::from(b)));
    !sum
}

/// A valid footer: its disk type and the virtual size.
fn footer(bytes: &[u8]) -> Option<(u32, u64, u64)> {
    let footer = bytes.get(..FOOTER).filter(|f| f.starts_with(b"conectix"))?;
    (checksum(footer, 64) == be32(footer, 64)).then(|| (be32(footer, 60), be64(footer, 48), be64(footer, 16)))
}

/// A VHD with a footer copy at its start: dynamic, or differencing (refused).
pub fn open(file: Data) -> io::Result<Disk> {
    let (kind, size, data_offset) =
        footer((*file).as_ref()).ok_or_else(|| bad(NAME, "the footer is damaged (bad checksum)"))?;
    dynamic(file, kind, size, data_offset)
}

/// A VHD recognised by the footer at the end of `path`: fixed, or a dynamic one that lacks
/// the copy at the start. `Ok(None)` when the file does not end with a footer.
pub fn open_fixed(path: &Path) -> io::Result<Option<Disk>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut tail = [0u8; FOOTER];
    if len < FOOTER as u64
        || file.seek(SeekFrom::Start(len - FOOTER as u64)).is_err()
        || file.read_exact(&mut tail).is_err()
    {
        return Ok(None);
    }
    let Some((kind, size, data_offset)) = footer(&tail) else { return Ok(None) };
    let data = super::vdisk::map_data(path)?;
    if kind != TYPE_FIXED {
        return dynamic(data, kind, size, data_offset).map(Some);
    }
    let room = len - FOOTER as u64;
    if size == 0 || size > room {
        return Err(bad(NAME, format!("the footer says {size} bytes but the file holds {room} before the footer")));
    }
    let mut notes = vec![format!(
        "VHD fixed virtual disk read directly: {size} bytes (the 512-byte footer at the end is not part of the disk)"
    )];
    if size < room {
        notes.push(format!("{NAME}: {} bytes follow the disk before the footer and are not read", room - size));
    }
    Ok(Some(Disk { reader: Arc::new(Fixed { data, size }), notes }))
}

struct Fixed {
    data: Data,
    size: u64,
}

impl ReadAt for Fixed {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.size).ok_or_else(super::vdisk::eof)?;
        let src = slice((*self.data).as_ref(), offset, (end - offset) as usize).ok_or_else(super::vdisk::eof)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

pub struct Vhd {
    file: Data,
    size: u64,
    block_size: u64,
    table: u64,
    /// Bytes of the sector bitmap that starts every block.
    bitmap_len: u64,
}

fn dynamic(file: Data, kind: u32, size: u64, data_offset: u64) -> io::Result<Disk> {
    if kind != TYPE_DYNAMIC && kind != TYPE_DIFFERENCING {
        return Err(bad(NAME, format!("disk type {kind} with a footer at the start is not a dynamic disk")));
    }
    let bytes: &[u8] = (*file).as_ref();
    let header = slice(bytes, data_offset, DYNAMIC_HEADER)
        .filter(|h| h.starts_with(b"cxsparse"))
        .ok_or_else(|| bad(NAME, "the dynamic disk header is missing"))?;
    if checksum(header, 36) != be32(header, 36) {
        return Err(bad(NAME, "the dynamic disk header fails its checksum"));
    }
    if kind == TYPE_DIFFERENCING {
        // The parent's name: UTF-16 big endian, zero terminated.
        let units: Vec<u16> =
            header[64..576].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
        let parent = super::vdisk::printable(&String::from_utf16_lossy(&units));
        return Err(refuse(
            NAME,
            format!("the disk is a differencing disk with parent {parent}; consolidate the chain first (qemu-img convert -O raw)"),
        ));
    }
    let (table, entries, block_size) = (be64(header, 16), u64::from(be32(header, 28)), be32(header, 32));
    if !BLOCK_RANGE.contains(&block_size) || !block_size.is_power_of_two() {
        return Err(bad(NAME, format!("implausible block size {block_size}")));
    }
    let block_size = u64::from(block_size);
    if size > i64::MAX as u64 {
        return Err(bad(NAME, "implausible virtual size"));
    }
    let needed = size.div_ceil(block_size);
    if entries < needed {
        return Err(bad(NAME, format!("the block table has {entries} entries but the size needs {needed}")));
    }
    if usize::try_from(entries * 4).ok().and_then(|n| slice(bytes, table, n)).is_none() {
        return Err(bad(NAME, "the block allocation table lies outside the file"));
    }
    let bitmap_len = (block_size / 512).div_ceil(8).next_multiple_of(512);
    let notes = vec![format!("VHD dynamic virtual disk read directly: {size} bytes, {} KiB blocks", block_size >> 10)];
    Ok(Disk { reader: Arc::new(Vhd { file, size, block_size, table, bitmap_len }), notes })
}

impl ReadAt for Vhd {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let bytes: &[u8] = (*self.file).as_ref();
        for_blocks(self.size, self.block_size, offset, buf, |start, within, out| {
            let entry = slice(bytes, self.table + start / self.block_size * 4, 4)
                .ok_or_else(|| bad(NAME, "the block table is cut off"))?;
            let sector = be32(entry, 0);
            if sector == UNALLOCATED {
                out.fill(0);
                return Ok(());
            }
            let block = u64::from(sector) * 512;
            let bitmap = slice(bytes, block, self.bitmap_len as usize)
                .ok_or_else(|| bad(NAME, format!("the block at sector {sector} lies outside the file")))?;
            let data = block + self.bitmap_len;
            // Sector runs with the same bit are copied or cleared together.
            let (mut at, end) = (within, within + out.len());
            while at < end {
                let first = at / 512;
                let present = bitmap.get(first / 8).is_some_and(|b| b >> (7 - first % 8) & 1 != 0);
                let mut stop = ((first + 1) * 512).min(end);
                while stop < end {
                    let s = stop / 512;
                    if bitmap.get(s / 8).is_some_and(|b| b >> (7 - s % 8) & 1 != 0) != present {
                        break;
                    }
                    stop = ((s + 1) * 512).min(end);
                }
                let part = out.get_mut(at - within..stop - within).ok_or_else(super::vdisk::eof)?;
                if present {
                    let src = slice(bytes, data + at as u64, part.len())
                        .ok_or_else(|| bad(NAME, format!("the block at sector {sector} lies outside the file")))?;
                    part.copy_from_slice(src);
                } else {
                    part.fill(0);
                }
                at = stop;
            }
            Ok(())
        })
    }

    fn size(&self) -> u64 {
        self.size
    }
}

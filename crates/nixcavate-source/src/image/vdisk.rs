//! Virtual machine disks read directly: qcow2, VMDK, VHD, VHDX and VDI.
//!
//! Each format is a [`ReadAt`] over the virtual disk's bytes, built on the memory-mapped file
//! (or files, for a split VMDK). Mapping and block tables are never copied: a lookup reads the
//! table entry straight out of the mapping, so the only memory a reader holds beyond the mapping
//! is [`BlockCache`], the few decompressed clusters of qcow2 and `streamOptimized` VMDK.
//!
//! Disks that cannot be read faithfully are refused with the reason instead of read wrongly:
//! encryption, backing files and parents (snapshots, linked clones), external data files and
//! the other cases named in `docs/LIMITATIONS.md`. Everything in the files is untrusted: every
//! offset is checked against the file, no allocation is sized by a field of the file, and a
//! block that decompresses to more than its size is an error.

use super::Shared;
use crate::map;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The bytes of one file of a disk: a mapping, or an empty buffer for an empty file.
pub(super) type Data = Box<dyn AsRef<[u8]> + Send + Sync>;

/// An opened disk and what to tell the user about it: the first note names the format read,
/// the others are warnings.
pub(super) struct Disk {
    pub reader: Shared,
    pub notes: Vec<String>,
}

/// Decompressed blocks kept for reuse: at most this many, and at most [`CACHE_BYTES`] of them.
const CACHE_BLOCKS: usize = 16;
const CACHE_BYTES: u64 = 64 << 20;

pub(super) fn bad(format: &str, msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{format}: {}", msg.into()))
}

/// A virtual disk that is understood but cannot be read faithfully.
pub(super) fn refuse(format: &str, msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{format}: {}", msg.into()))
}

pub(super) fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the image")
}

/// `len` bytes of `data` at `offset`, if they are all there.
pub(super) fn slice(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(len)?)
}

/// A file mapped read-only (an empty file is an empty buffer, as it cannot be mapped).
pub(super) fn map_data(path: &Path) -> io::Result<Data> {
    if std::fs::metadata(path)?.len() == 0 {
        return Ok(Box::new(Vec::<u8>::new()));
    }
    Ok(Box::new(map(path)?))
}

/// Calls `f(block start, offset within the block, part of buf)` for each piece of the read that
/// falls in one block of `block` bytes. Reads past `size` are `UnexpectedEof`.
pub(super) fn for_blocks(
    size: u64,
    block: u64,
    offset: u64,
    buf: &mut [u8],
    mut f: impl FnMut(u64, usize, &mut [u8]) -> io::Result<()>,
) -> io::Result<()> {
    let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= size).ok_or_else(eof)?;
    let block = block.max(1);
    let (mut position, mut done) = (offset, 0usize);
    while position < end {
        let start = position - position % block;
        let within = position - start;
        let n = (block - within).min(end - position) as usize;
        let part = buf.get_mut(done..done + n).ok_or_else(eof)?;
        f(start, within as usize, part)?;
        position += n as u64;
        done += n;
    }
    Ok(())
}

struct Slot {
    key: (u64, u64),
    used: u64,
    data: Arc<Vec<u8>>,
}

#[derive(Default)]
struct Slots {
    tick: u64,
    slots: Vec<Slot>,
}

/// Decompressed blocks by key. A mutex rather than a per-thread cache: tasks read in parallel,
/// and the lock is held only to look up or insert, never while a block is being decompressed.
pub(super) struct BlockCache {
    slots: Mutex<Slots>,
    room: usize,
}

impl BlockCache {
    /// A cache for blocks of up to `block_size` bytes.
    pub fn new(block_size: u64) -> BlockCache {
        let room = (CACHE_BYTES / block_size.max(1)).clamp(1, CACHE_BLOCKS as u64) as usize;
        BlockCache { slots: Mutex::default(), room }
    }

    /// The block under `key`, made by `make` when it is not cached.
    pub fn get(&self, key: (u64, u64), make: impl FnOnce() -> io::Result<Vec<u8>>) -> io::Result<Arc<Vec<u8>>> {
        let lock = || self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let mut cache = lock();
            cache.tick += 1;
            let tick = cache.tick;
            if let Some(slot) = cache.slots.iter_mut().find(|s| s.key == key) {
                slot.used = tick;
                return Ok(slot.data.clone());
            }
        }
        let data = Arc::new(make()?);
        let mut cache = lock();
        cache.tick += 1;
        let slot = Slot { key, used: cache.tick, data: data.clone() };
        if cache.slots.len() < self.room {
            cache.slots.push(slot);
        } else if let Some(oldest) = cache.slots.iter_mut().min_by_key(|s| s.used) {
            *oldest = slot;
        }
        Ok(data)
    }
}

/// `text` with control characters made visible, for names that come from the evidence.
pub(super) fn printable(text: &str) -> String {
    text.chars().flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] }).collect()
}

/// Opens `path` when its first bytes (`head`) or its last 512 bytes say it is a virtual disk.
/// `Ok(None)` when it is not one.
pub(super) fn open(path: &Path, head: &[u8]) -> io::Result<Option<Disk>> {
    let disk = if head.starts_with(b"QFI\xfb") {
        super::qcow2::open(map_data(path)?)?
    } else if head.starts_with(b"KDMV") || head.starts_with(b"# Disk DescriptorFile") {
        super::vmdk::open(path, head)?
    } else if head.starts_with(b"COWD") {
        return Err(refuse(
            "VMDK",
            "this is an ESXi snapshot or linked-clone delta (COWD, vmfsSparse); consolidate the snapshots first",
        ));
    } else if head.starts_with(b"vhdxfile") {
        super::vhdx::open(map_data(path)?)?
    } else if head.starts_with(b"<<< ") && head.windows(10).any(|w| w == b"Disk Image") {
        super::vdi::open(map_data(path)?)?
    } else if head.starts_with(b"conectix") {
        super::vhd::open(map_data(path)?)?
    } else if let Some(disk) = super::vhd::open_fixed(path)? {
        disk
    } else {
        return Ok(None);
    };
    Ok(Some(disk))
}

/// CRC-32C (Castagnoli), the checksum of VHDX headers and region tables.
pub(super) fn crc32c(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
                bit += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };
    let mut crc = !0u32;
    for &byte in data {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests;

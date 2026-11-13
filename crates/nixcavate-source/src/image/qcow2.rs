//! QEMU qcow2 (versions 2 and 3) reader, written from QEMU's `docs/interop/qcow2.txt`.
//!
//! All fields are big endian. The header gives the cluster size (`cluster_bits`, 9 to 21), the
//! virtual size and the L1 table. An L1 entry points at an L2 table (one cluster of entries, or
//! of 16-byte entries with extended L2); an L2 entry says where the cluster is:
//!
//! * standard: bits 9 to 55 are the cluster's file offset. An offset of 0 is unallocated, which
//!   reads as zeros (a backing file is refused, so there is nothing to fall back to). Bit 0
//!   (version 3 only) marks a cluster that reads as zeros whatever its offset.
//! * compressed (bit 62): a byte offset and a count of 512-byte sectors, raw deflate or zstd
//!   (the header's compression type) that inflates to one cluster. It may span host clusters.
//! * extended L2 entries carry a second u64 of per-subcluster (cluster / 32) allocated and
//!   zero bits.
//!
//! Refused with the reason: encryption, a backing file (it is named), an external data file,
//! unknown incompatible features. The "dirty" and "corrupt" bits give a warning and the data
//! are read anyway. Snapshots are not followed: the active state is read.
//!
//! Tables are read in place from the mapping. L1 must lie in the file and cover the virtual
//! size; an L2 table or cluster outside the file is an error at read time, not a panic.

use super::vdisk::{bad, for_blocks, printable, refuse, slice, BlockCache, Data, Disk};
use nixcavate_fs::{be32, be64, ReadAt};
use std::io::{self, Read};
use std::sync::Arc;

const NAME: &str = "qcow2";
const HEADER_V2: usize = 72;
const HEADER_V3_MIN: usize = 104;
const INCOMPAT_DIRTY: u64 = 1;
const INCOMPAT_CORRUPT: u64 = 1 << 1;
const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
const INCOMPAT_KNOWN: u64 = 0x1f;
const EXT_END: u32 = 0;
const EXT_EXTERNAL_DATA_NAME: u32 = 0x4441_5441;
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COMPRESSED: u64 = 1 << 62;
/// A backing or data file name is at most this long (QEMU's limit is 1023).
const MAX_NAME: usize = 1023;

pub struct Qcow2 {
    file: Data,
    version: u32,
    cluster_bits: u32,
    size: u64,
    l1_offset: u64,
    l1_size: u64,
    /// Entries per L2 table.
    l2_entries: u64,
    extended: bool,
    zstd: bool,
    cache: BlockCache,
}

/// Where the bytes of one cluster (or subcluster) are.
enum Place {
    Zeros,
    /// Offset in the file of the first byte wanted.
    File(u64),
    Compressed {
        offset: u64,
        len: usize,
    },
}

pub fn open(file: Data) -> io::Result<Disk> {
    let head: &[u8] = (*file).as_ref();
    let mut notes = Vec::new();
    if head.len() < HEADER_V2 {
        return Err(bad(NAME, "the file is too short for a header"));
    }
    let version = be32(head, 4);
    match version {
        2 | 3 => {}
        1 => return Err(refuse(NAME, "this is the old qcow format (version 1), which is not supported")),
        v => return Err(refuse(NAME, format!("version {v} is not supported"))),
    }
    let cluster_bits = be32(head, 20);
    if !(9..=21).contains(&cluster_bits) {
        return Err(bad(NAME, format!("cluster_bits {cluster_bits} is outside 9 to 21")));
    }
    let cluster = 1u64 << cluster_bits;
    let crypt = be32(head, 32);
    if crypt != 0 {
        let kind = match crypt {
            1 => "AES",
            2 => "LUKS",
            _ => "an unknown method of",
        };
        return Err(refuse(NAME, format!("the disk is encrypted ({kind} encryption); decrypt it first")));
    }

    let (mut incompat, mut zstd) = (0u64, false);
    if version == 3 {
        if head.len() < HEADER_V3_MIN {
            return Err(bad(NAME, "the file is too short for a version 3 header"));
        }
        incompat = be64(head, 72);
        let header_len = be32(head, 100) as usize;
        if header_len < HEADER_V3_MIN || header_len as u64 > cluster {
            return Err(bad(NAME, format!("implausible header length {header_len}")));
        }
        if incompat & !INCOMPAT_KNOWN != 0 {
            return Err(refuse(
                NAME,
                format!(
                    "unknown incompatible feature bits {:#x}; a newer QEMU wrote this disk",
                    incompat & !INCOMPAT_KNOWN
                ),
            ));
        }
        if incompat & INCOMPAT_EXTERNAL_DATA != 0 {
            let name = extension_name(head, header_len, cluster).unwrap_or_default();
            return Err(refuse(
                NAME,
                format!("the disk keeps its data in an external data file ({name}); it is not read"),
            ));
        }
        if incompat & INCOMPAT_COMPRESSION != 0 && header_len > HEADER_V3_MIN {
            match head.get(HEADER_V3_MIN) {
                Some(0) => {}
                Some(1) => zstd = true,
                other => return Err(refuse(NAME, format!("compression type {other:?} is not supported"))),
            }
        }
        if incompat & INCOMPAT_DIRTY != 0 {
            notes.push(format!("{NAME}: the disk was not closed cleanly (dirty bit); its data are read as they are"));
        }
        if incompat & INCOMPAT_CORRUPT != 0 {
            notes.push(format!(
                "{NAME}: the disk is marked corrupt by the program that wrote it; contents may be wrong"
            ));
        }
    }

    // A backing file means unallocated clusters live in another disk: refuse and name it.
    let backing_offset = be64(head, 8);
    let backing_size = be32(head, 16) as usize;
    if backing_size > 0 {
        let name = slice(head, backing_offset, backing_size.min(MAX_NAME))
            .map(|n| printable(&String::from_utf8_lossy(n)))
            .unwrap_or_else(|| "name unreadable".into());
        return Err(refuse(
            NAME,
            format!("the disk has a backing file ({name}); read the chain consolidated: qemu-img convert -O raw <disk> disk.raw"),
        ));
    }

    let size = be64(head, 24);
    if size > i64::MAX as u64 {
        return Err(bad(NAME, "implausible virtual size"));
    }
    let extended = incompat & INCOMPAT_EXTENDED_L2 != 0;
    if extended && cluster_bits < 14 {
        return Err(bad(NAME, "extended L2 entries need a cluster of at least 16 KiB"));
    }
    let l2_entries = cluster / if extended { 16 } else { 8 };
    let l1_size = u64::from(be32(head, 36));
    let l1_offset = be64(head, 40);
    let needed = size.div_ceil(cluster).div_ceil(l2_entries);
    if l1_size < needed {
        return Err(bad(NAME, format!("the L1 table has {l1_size} entries but the size needs {needed}")));
    }
    let l1_bytes = l1_size.checked_mul(8).and_then(|b| usize::try_from(b).ok());
    if l1_bytes.and_then(|b| slice(head, l1_offset, b)).is_none() {
        return Err(bad(NAME, "the L1 table lies outside the file"));
    }
    let snapshots = be32(head, 60);
    if snapshots > 0 {
        notes.push(format!("{NAME}: {snapshots} internal snapshot(s) are ignored; the active state is read"));
    }
    notes.insert(
        0,
        format!(
            "qcow2 version {version} virtual disk read directly: {size} bytes, {} clusters{}{}",
            if cluster >= 1024 { format!("{} KiB", cluster >> 10) } else { format!("{cluster} byte") },
            if extended { ", extended L2" } else { "" },
            if zstd { ", zstd compression" } else { "" },
        ),
    );
    let reader = Qcow2 {
        file,
        version,
        cluster_bits,
        size,
        l1_offset,
        l1_size,
        l2_entries,
        extended,
        zstd,
        cache: BlockCache::new(cluster),
    };
    Ok(Disk { reader: Arc::new(reader), notes })
}

/// The data file name of an external-data-file extension, if the extensions have one.
fn extension_name(head: &[u8], header_len: usize, cluster: u64) -> Option<String> {
    let area = head.get(header_len.next_multiple_of(8)..(cluster as usize).min(head.len()))?;
    let mut at = 0usize;
    while let Some(entry) = area.get(at..at + 8) {
        let (kind, len) = (be32(entry, 0), be32(entry, 4) as usize);
        if kind == EXT_END {
            break;
        }
        let body = area.get(at + 8..at + 8 + len)?;
        if kind == EXT_EXTERNAL_DATA_NAME {
            return Some(printable(&String::from_utf8_lossy(body)));
        }
        at = at.checked_add(8 + len.checked_next_multiple_of(8)?)?;
    }
    None
}

impl Qcow2 {
    fn bytes(&self) -> &[u8] {
        (*self.file).as_ref()
    }

    fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    /// Where the cluster holding virtual offset `start` is, and for extended L2 the
    /// subcluster of `start`.
    fn locate(&self, start: u64) -> io::Result<Place> {
        let cluster = start >> self.cluster_bits;
        let (l1_index, l2_index) = (cluster / self.l2_entries, cluster % self.l2_entries);
        if l1_index >= self.l1_size {
            return Ok(Place::Zeros);
        }
        let l1 =
            slice(self.bytes(), self.l1_offset + l1_index * 8, 8).ok_or_else(|| bad(NAME, "L1 table is cut off"))?;
        let l2_table = be64(l1, 0) & OFFSET_MASK;
        if l2_table == 0 {
            return Ok(Place::Zeros);
        }
        if l2_table % self.cluster_size() != 0 {
            return Err(bad(NAME, format!("the L2 table at {l2_table} is not cluster aligned")));
        }
        let entry_size = if self.extended { 16 } else { 8 };
        let entry_at = l2_table + l2_index * entry_size;
        let entry = slice(self.bytes(), entry_at, entry_size as usize)
            .ok_or_else(|| bad(NAME, format!("the L2 table at {l2_table} lies outside the file")))?;
        let word = be64(entry, 0);
        if word & COMPRESSED != 0 {
            let shift = 62 - (self.cluster_bits - 8);
            let offset = word & ((1u64 << shift) - 1);
            let sectors = ((word >> shift) & ((1u64 << (self.cluster_bits - 8)) - 1)) + 1;
            let len = (sectors * 512 - (offset & 511)) as usize;
            return Ok(Place::Compressed { offset, len });
        }
        let host = word & OFFSET_MASK;
        let zero_flag = self.version == 3 && word & 1 != 0;
        if self.extended {
            let bitmap = be64(entry, 8);
            let sub_size = self.cluster_size() / 32;
            let sub = ((start & (self.cluster_size() - 1)) / sub_size) as u32;
            let allocated = bitmap >> sub & 1 != 0;
            let zero = bitmap >> (32 + sub) & 1 != 0;
            return match (allocated, zero || zero_flag) {
                (true, true) => Err(bad(NAME, "a subcluster is both allocated and zero")),
                (_, true) | (false, false) => Ok(Place::Zeros),
                (true, false) if host == 0 => Err(bad(NAME, "an allocated subcluster has no host cluster")),
                (true, false) => Ok(Place::File(self.checked_host(host)?)),
            };
        }
        if zero_flag || host == 0 {
            return Ok(Place::Zeros);
        }
        Ok(Place::File(self.checked_host(host)?))
    }

    fn checked_host(&self, host: u64) -> io::Result<u64> {
        if host % self.cluster_size() != 0 {
            return Err(bad(NAME, format!("the cluster at {host} is not cluster aligned")));
        }
        Ok(host)
    }

    /// The decompressed cluster at virtual offset `start` (aligned to a cluster).
    fn inflate(&self, start: u64, offset: u64, len: usize) -> io::Result<Arc<Vec<u8>>> {
        self.cache.get((0, start >> self.cluster_bits), || {
            let file = self.bytes();
            let at = usize::try_from(offset)
                .ok()
                .filter(|&a| a < file.len())
                .ok_or_else(|| bad(NAME, format!("the compressed cluster at {offset} lies outside the file")))?;
            let raw = file.get(at..at.saturating_add(len).min(file.len())).unwrap_or_default();
            let cluster = self.cluster_size();
            let expected = cluster.min(self.size.saturating_sub(start)) as usize;
            let mut out = Vec::with_capacity(expected);
            // One byte more than a cluster tells a cluster that inflates too far from one that fits.
            let limit = cluster + 1;
            let result = if self.zstd {
                zstd::stream::read::Decoder::new(raw).and_then(|d| d.single_frame().take(limit).read_to_end(&mut out))
            } else {
                flate2::read::DeflateDecoder::new(raw).take(limit).read_to_end(&mut out)
            };
            result.map_err(|e| bad(NAME, format!("the compressed cluster at {offset}: {e}")))?;
            if out.len() as u64 > cluster {
                return Err(bad(NAME, format!("the compressed cluster at {offset} inflates beyond the cluster size")));
            }
            if out.len() < expected {
                return Err(bad(
                    NAME,
                    format!("the compressed cluster at {offset} inflated to {} of {expected} bytes", out.len()),
                ));
            }
            Ok(out)
        })
    }
}

impl ReadAt for Qcow2 {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        // Extended L2 describes each 1/32 of a cluster separately.
        let block = if self.extended { self.cluster_size() / 32 } else { self.cluster_size() };
        for_blocks(self.size, block, offset, buf, |start, within, out| match self.locate(start)? {
            Place::Zeros => {
                out.fill(0);
                Ok(())
            }
            Place::File(host) => {
                let inside = start & (self.cluster_size() - 1);
                let from = host + inside + within as u64;
                let src = slice(self.bytes(), from, out.len())
                    .ok_or_else(|| bad(NAME, format!("the cluster at {host} lies outside the file")))?;
                out.copy_from_slice(src);
                Ok(())
            }
            Place::Compressed { offset, len } => {
                let cluster_start = start & !(self.cluster_size() - 1);
                let data = self.inflate(cluster_start, offset, len)?;
                let from = (start - cluster_start) as usize + within;
                let part = data.get(from..from + out.len()).ok_or_else(|| bad(NAME, "short compressed cluster"))?;
                out.copy_from_slice(part);
                Ok(())
            }
        })
    }

    fn size(&self) -> u64 {
        self.size
    }
}

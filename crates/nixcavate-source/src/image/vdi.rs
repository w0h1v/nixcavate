//! VirtualBox VDI reader (header version 1.1), written from VirtualBox's `VDICore.h`.
//!
//! Little endian. A 64-byte text banner, the signature `0xBEDA107F` (u32 at 64), the version
//! (u32 at 68, major in the high half) and a header holding the image type (1 dynamic, 2 fixed,
//! 3 undo, 4 differencing), the offsets of the block map and the data, the disk size, the block
//! size and the block count. The block map has one u32 per block: `0xFFFFFFFF` is unallocated
//! and `0xFFFFFFFE` is zeros (both read as zeros); any other value is the block's index in the
//! data area, at `data offset + index * (block size + extra)`. Fixed images use the same map.
//! Undo and differencing images need another file and are refused.

use super::vdisk::{bad, for_blocks, refuse, slice, Data, Disk};
use nixcavate_fs::{le32, le64, ReadAt};
use std::io;
use std::sync::Arc;

const NAME: &str = "VDI";
const SIGNATURE: u32 = 0xBEDA_107F;
/// The header after the 72-byte preheader is 0x180 bytes in version 1.1.
const HEADER_MIN: usize = 0x180;
const PREHEADER: usize = 72;
const FREE: u32 = 0xFFFF_FFFF;
const ZERO: u32 = 0xFFFF_FFFE;
const MAX_BLOCK: u32 = 1 << 30;

pub struct Vdi {
    file: Data,
    size: u64,
    block_size: u64,
    /// The data area's offset and the stride of its blocks.
    data: u64,
    stride: u64,
    map: u64,
}

pub fn open(file: Data) -> io::Result<Disk> {
    let bytes: &[u8] = (*file).as_ref();
    let head = bytes.get(..PREHEADER + HEADER_MIN).ok_or_else(|| bad(NAME, "the file is too short for a header"))?;
    if le32(head, 64) != SIGNATURE {
        return Err(bad(NAME, "no VDI signature"));
    }
    let version = le32(head, 68);
    if version != 0x0001_0001 {
        return Err(refuse(
            NAME,
            format!("header version {}.{} is not supported (only 1.1)", version >> 16, version & 0xffff),
        ));
    }
    let header_size = le32(head, 72) as usize;
    if !(HEADER_MIN..=4096).contains(&header_size) {
        return Err(bad(NAME, format!("implausible header size {header_size}")));
    }
    let kind = match le32(head, 76) {
        1 => "dynamic",
        2 => "fixed",
        3 | 4 => {
            return Err(refuse(
                NAME,
                "the disk is an undo or differencing image; consolidate the chain first (VBoxManage clonemedium)",
            ));
        }
        other => return Err(bad(NAME, format!("unknown image type {other}"))),
    };
    let (map, data) = (u64::from(le32(head, 340)), u64::from(le32(head, 344)));
    let size = le64(head, 368);
    let (block_size, extra, blocks) = (le32(head, 376), le32(head, 380), u64::from(le32(head, 384)));
    if block_size == 0 || block_size > MAX_BLOCK || block_size % 512 != 0 || extra > 1 << 20 {
        return Err(bad(NAME, format!("implausible block size {block_size} (extra {extra})")));
    }
    let block_size = u64::from(block_size);
    if size > i64::MAX as u64 {
        return Err(bad(NAME, "implausible disk size"));
    }
    let needed = size.div_ceil(block_size);
    if blocks < needed {
        return Err(bad(NAME, format!("the block map has {blocks} entries but the size needs {needed}")));
    }
    if usize::try_from(blocks * 4).ok().and_then(|n| slice(bytes, map, n)).is_none() {
        return Err(bad(NAME, "the block map lies outside the file"));
    }
    let notes = vec![format!("VDI {kind} virtual disk read directly: {size} bytes, {} KiB blocks", block_size >> 10)];
    Ok(Disk {
        reader: Arc::new(Vdi { file, size, block_size, data, stride: block_size + u64::from(extra), map }),
        notes,
    })
}

impl ReadAt for Vdi {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let bytes: &[u8] = (*self.file).as_ref();
        for_blocks(self.size, self.block_size, offset, buf, |start, within, out| {
            let entry = slice(bytes, self.map + start / self.block_size * 4, 4)
                .ok_or_else(|| bad(NAME, "the block map is cut off"))?;
            match le32(entry, 0) {
                FREE | ZERO => out.fill(0),
                index => {
                    // index < 2^32 and stride <= 2^30 + 2^20, so this cannot overflow.
                    let at = self.data + u64::from(index) * self.stride + within as u64;
                    let src = slice(bytes, at, out.len())
                        .ok_or_else(|| bad(NAME, format!("block {index} lies outside the file")))?;
                    out.copy_from_slice(src);
                }
            }
            Ok(())
        })
    }

    fn size(&self) -> u64 {
        self.size
    }
}

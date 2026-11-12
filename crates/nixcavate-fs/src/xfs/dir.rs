//! XFS directory listings: shortform directories inside the inode and directory data blocks.

use crate::{be16, be32, be64, Entries, Error, Result};

/// Adds an entry unless it is the directory's own `.` or `..` record.
fn add(out: &mut Entries, ino: u64, name: &[u8]) {
    if name != b"." && name != b".." {
        out.push(ino, name);
    }
}

/// Shortform directory: a header with the parent, then packed entries inside the inode.
pub(super) fn parse_shortform(data: &[u8], ftype: bool, out: &mut Entries) -> Result<()> {
    let bad = || Error::corrupt("shortform directory");
    let count = usize::from(*data.first().ok_or_else(bad)?);
    let ino_size = if data.get(1).copied().unwrap_or(0) != 0 { 8 } else { 4 };
    let mut pos = 2 + ino_size;
    for _ in 0..count {
        let name_len = usize::from(*data.get(pos).ok_or_else(bad)?);
        let name = data.get(pos + 3..pos + 3 + name_len).ok_or_else(bad)?;
        let ino_at = pos + 3 + name_len + usize::from(ftype);
        let ino_bytes = data.get(ino_at..ino_at + ino_size).ok_or_else(bad)?;
        let ino = if ino_size == 8 { be64(ino_bytes, 0) } else { u64::from(be32(ino_bytes, 0)) };
        if name_len == 0 {
            return Err(bad());
        }
        add(out, ino, name);
        pos = ino_at + ino_size;
    }
    Ok(())
}

/// One directory data block (`XD2B`/`XDB3` single-block form or `XD2D`/`XDD3` data block).
pub(super) fn parse_data_block(block: &[u8], v5: bool, ftype: bool, out: &mut Entries) -> Result<()> {
    let (header, single) = match (block.get(0..4), v5) {
        (Some(b"XD2B"), false) => (16, true),
        (Some(b"XD2D"), false) => (16, false),
        (Some(b"XDB3"), true) => (64, true),
        (Some(b"XDD3"), true) => (64, false),
        _ => return Err(Error::corrupt("directory block: bad magic")),
    };
    let mut end = block.len();
    if single {
        // The block tail (leaf count, stale count) and the leaf entries end the block.
        let leaves = be32(block, end.saturating_sub(8)) as usize;
        end = end
            .checked_sub(8)
            .and_then(|e| e.checked_sub(leaves.checked_mul(8)?))
            .filter(|&e| e >= header)
            .ok_or_else(|| Error::corrupt("directory block tail"))?;
    }
    let mut pos = header;
    while pos < end {
        let rest = &block[pos..end];
        if be16(rest, 0) == 0xffff {
            let len = usize::from(be16(rest, 2));
            if len < 8 || len % 8 != 0 || len > rest.len() {
                return Err(Error::corrupt("directory free space entry"));
            }
            pos += len;
            continue;
        }
        let name_len = usize::from(rest.get(8).copied().unwrap_or(0));
        let len = (8 + 1 + name_len + usize::from(ftype) + 2 + 7) & !7;
        if name_len == 0 || len > rest.len() {
            return Err(Error::corrupt("directory entry"));
        }
        add(out, be64(rest, 0), &rest[9..9 + name_len]);
        pos += len;
    }
    Ok(())
}

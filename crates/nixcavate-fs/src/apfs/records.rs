//! File-system records ("File-System Objects", "Data Streams", "Extended Fields" and
//! "Snapshot Metadata" in the Apple File System Reference).

use std::cmp::Ordering;

use super::Snapshot;
use crate::{le16, le32, le64};

const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const OBJ_TYPE_SHIFT: u32 = 60;

pub(crate) const APFS_TYPE_SNAP_METADATA: u8 = 1;
pub(crate) const APFS_TYPE_INODE: u8 = 3;
pub(crate) const APFS_TYPE_XATTR: u8 = 4;
pub(crate) const APFS_TYPE_FILE_EXTENT: u8 = 8;
pub(crate) const APFS_TYPE_DIR_REC: u8 = 9;

const INO_EXT_TYPE_DSTREAM: u8 = 8;
const XATTR_DATA_STREAM: u16 = 0x1;
const XATTR_DATA_EMBEDDED: u16 = 0x2;
const J_DREC_LEN_MASK: u32 = 0x3ff;
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;
/// `j_inode_val_t` up to its extended fields.
const INODE_FIXED: usize = 92;

/// `obj_id_and_type` of a `j_key_t`.
pub(crate) fn split_key(key: &[u8]) -> Option<(u64, u8)> {
    let v = (key.len() >= 8).then(|| le64(key, 0))?;
    Some((v & OBJ_ID_MASK, (v >> OBJ_TYPE_SHIFT) as u8))
}

/// Orders a file-system key against (object id, record type).
pub(crate) fn fs_cmp(key: &[u8], oid: u64, ty: u8) -> Ordering {
    split_key(key).map_or(Ordering::Less, |k| k.cmp(&(oid, ty)))
}

/// Nanoseconds since the epoch; zero means unset.
pub(crate) fn time(ns: u64) -> Option<i64> {
    i64::try_from(ns).ok().filter(|&t| t != 0)
}

/// The fields of `j_inode_val_t` that a walk reports.
pub(crate) struct Inode {
    pub private_id: u64,
    pub created: u64,
    pub modified: u64,
    pub changed: u64,
    pub accessed: u64,
    /// `nlink` for files, `nchildren` for directories.
    pub nlink: i32,
    pub bsd_flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    /// Logical and allocated size from the `j_dstream_t` extended field, if any.
    pub size: u64,
    pub alloced: u64,
}

pub(crate) fn parse_inode(v: &[u8]) -> Option<Inode> {
    if v.len() < INODE_FIXED {
        return None;
    }
    let dstream = xfield(&v[INODE_FIXED..], INO_EXT_TYPE_DSTREAM).unwrap_or(&[]);
    Some(Inode {
        private_id: le64(v, 8),
        created: le64(v, 16),
        modified: le64(v, 24),
        changed: le64(v, 32),
        accessed: le64(v, 40),
        nlink: le32(v, 56) as i32,
        bsd_flags: le32(v, 68),
        uid: le32(v, 72),
        gid: le32(v, 76),
        mode: le16(v, 80),
        size: le64(dstream, 0),
        alloced: le64(dstream, 8),
    })
}

/// The data of extended field `want` in an `xf_blob_t`.
fn xfield(blob: &[u8], want: u8) -> Option<&[u8]> {
    let count = usize::from(le16(blob, 0));
    let mut data = 4 + count * 4;
    for i in 0..count {
        let header = 4 + 4 * i;
        let field = blob.get(header..header + 4)?;
        let (ty, size) = (field[0], usize::from(le16(field, 2)));
        if ty == want {
            return blob.get(data..data.checked_add(size)?);
        }
        data = data.checked_add(size.checked_add(7)? & !7)?;
    }
    None
}

/// A directory entry: name bytes (without the terminating NUL) and the child's inode number.
/// Hashed keys (`j_drec_hashed_key_t`) and plain keys (`j_drec_key_t`) are told apart by how
/// their length fields fit the key; `hashed` breaks a tie.
pub(crate) fn parse_drec<'k>(key: &'k [u8], val: &[u8], hashed: bool) -> Option<(&'k [u8], u64)> {
    let fits_hashed = key.len() >= 12 && 12 + (le32(key, 8) & J_DREC_LEN_MASK) as usize == key.len();
    let fits_plain = key.len() >= 10 && 10 + usize::from(le16(key, 8)) == key.len();
    let name = match (fits_hashed, fits_plain) {
        (true, false) => &key[12..],
        (false, true) => &key[10..],
        (true, true) if hashed => &key[12..],
        (true, true) => &key[10..],
        (false, false) => return None,
    };
    Some((strip_nul(name), (val.len() >= 8).then(|| le64(val, 0))?))
}

fn strip_nul(name: &[u8]) -> &[u8] {
    name.strip_suffix(&[0]).unwrap_or(name)
}

/// Where an extended attribute's value lives.
pub(crate) enum Xdata<'v> {
    Embedded(&'v [u8]),
    /// A data stream: file extents keyed by `oid`, `size` bytes long.
    Stream {
        oid: u64,
        size: u64,
    },
}

pub(crate) fn parse_xattr<'r>(key: &'r [u8], val: &'r [u8]) -> Option<(&'r [u8], Xdata<'r>)> {
    let name_len = usize::from(le16(key, 8));
    let name = strip_nul(key.get(10..10 + name_len)?);
    let flags = le16(val, 0);
    let len = usize::from(le16(val, 2));
    let data = val.get(4..4 + len)?;
    let xdata = if flags & XATTR_DATA_EMBEDDED != 0 {
        Xdata::Embedded(data)
    } else if flags & XATTR_DATA_STREAM != 0 && data.len() >= 16 {
        Xdata::Stream { oid: le64(data, 0), size: le64(data, 8) }
    } else {
        return None;
    };
    Some((name, xdata))
}

/// A `j_file_extent` record: (logical offset, length, physical block; 0 for a hole).
pub(crate) fn parse_extent(key: &[u8], val: &[u8]) -> Option<(u64, u64, u64)> {
    (key.len() >= 16 && val.len() >= 16).then(|| (le64(key, 8), le64(val, 0) & J_FILE_EXTENT_LEN_MASK, le64(val, 8)))
}

/// A `j_snap_metadata` record from a volume's snapshot metadata tree.
pub(crate) fn parse_snapshot(key: &[u8], val: &[u8]) -> Option<Snapshot> {
    let (xid, ty) = split_key(key)?;
    if ty != APFS_TYPE_SNAP_METADATA {
        return None;
    }
    let name_len = usize::from(le16(val, 48));
    let name = strip_nul(val.get(50..50 + name_len)?);
    Some(Snapshot { name: String::from_utf8_lossy(name).into_owned(), xid, created: time(le64(val, 16)) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(oid: u64, ty: u8) -> Vec<u8> {
        (oid | (u64::from(ty) << OBJ_TYPE_SHIFT)).to_le_bytes().to_vec()
    }

    #[test]
    fn directory_keys_hashed_and_plain() {
        let val = 42u64.to_le_bytes();
        let mut hashed = key(2, APFS_TYPE_DIR_REC);
        hashed.extend_from_slice(&((0xabcde << 10) | 4u32).to_le_bytes());
        hashed.extend_from_slice(b"abc\0");
        assert_eq!(parse_drec(&hashed, &val, true), Some((&b"abc"[..], 42)));
        let mut plain = key(2, APFS_TYPE_DIR_REC);
        plain.extend_from_slice(&5u16.to_le_bytes());
        plain.extend_from_slice(b"name\0");
        assert_eq!(parse_drec(&plain, &val, true), Some((&b"name"[..], 42)));
        assert_eq!(parse_drec(&plain[..12], &val, true), None);
    }

    #[test]
    fn snapshot_metadata() {
        let mut val = vec![0u8; 50];
        val[16..24].copy_from_slice(&1_700_000_000_123_456_789u64.to_le_bytes());
        val[48..50].copy_from_slice(&6u16.to_le_bytes());
        val.extend_from_slice(b"snap1\0");
        let snap = parse_snapshot(&key(0x1234, APFS_TYPE_SNAP_METADATA), &val).unwrap();
        assert_eq!(snap, Snapshot { name: "snap1".into(), xid: 0x1234, created: Some(1_700_000_000_123_456_789) });
        // Name records (type 11) in the same tree are not snapshots.
        assert!(parse_snapshot(&key(0x1234, 11), &val).is_none());
        assert!(parse_snapshot(&key(0x1234, APFS_TYPE_SNAP_METADATA), &val[..40]).is_none());
    }

    #[test]
    fn inode_extended_fields() {
        let mut v = vec![0u8; INODE_FIXED];
        v[80..82].copy_from_slice(&0o100644u16.to_le_bytes());
        // Two fields: a name (type 4, 5 bytes, padded to 8) then the data stream (type 8).
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&48u16.to_le_bytes());
        v.extend_from_slice(&[4, 0, 5, 0, 8, 0, 40, 0]);
        v.extend_from_slice(b"name\0\0\0\0");
        v.extend_from_slice(&1234u64.to_le_bytes());
        v.extend_from_slice(&[0u8; 32]);
        let inode = parse_inode(&v).unwrap();
        assert_eq!((inode.mode, inode.size), (0o100644, 1234));
        assert_eq!(parse_inode(&v[..INODE_FIXED]).unwrap().size, 0);
    }
}

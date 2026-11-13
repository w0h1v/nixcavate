//! Item bodies: inodes, directory entries, file extents and root items (`struct
//! btrfs_inode_item`, `btrfs_dir_item`, `btrfs_file_extent_item`, `btrfs_root_item`,
//! `btrfs_root_ref` in the kernel's `btrfs_tree.h`).

use super::tree::Key;
use crate::{le16, le32, le64};

pub(crate) const INODE_ITEM: u8 = 1;
pub(crate) const DIR_ITEM: u8 = 84;
pub(crate) const DIR_INDEX: u8 = 96;
pub(crate) const EXTENT_DATA: u8 = 108;
pub(crate) const ROOT_ITEM: u8 = 132;
pub(crate) const ROOT_BACKREF: u8 = 144;

/// Longest name a directory entry may hold (`BTRFS_NAME_LEN`).
pub(crate) const NAME_MAX: usize = 255;

/// The fields of an inode item a walk or a read uses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Inode {
    pub size: u64,
    /// Bytes of extents the file references (uncompressed), holes excluded.
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub atime: Option<i64>,
    pub ctime: Option<i64>,
    pub mtime: Option<i64>,
    pub otime: Option<i64>,
}

/// `struct btrfs_timespec`: signed seconds and nanoseconds. Zero, or nanoseconds of a second
/// or more, is no time.
fn time(b: &[u8], at: usize) -> Option<i64> {
    let sec = le64(b, at) as i64;
    let nsec = le32(b, at + 8);
    if (sec == 0 && nsec == 0) || nsec >= 1_000_000_000 {
        return None;
    }
    i64::try_from(i128::from(sec) * 1_000_000_000 + i128::from(nsec)).ok()
}

/// A 160-byte inode item (also the first part of a root item).
pub(crate) fn inode(b: &[u8]) -> Option<Inode> {
    (b.len() >= 160).then(|| Inode {
        size: le64(b, 16),
        nbytes: le64(b, 24),
        nlink: le32(b, 40),
        uid: le32(b, 44),
        gid: le32(b, 48),
        mode: le32(b, 52),
        atime: time(b, 112),
        ctime: time(b, 124),
        mtime: time(b, 136),
        otime: time(b, 148),
    })
}

/// Calls `f` with the location key and name of each entry packed in a `DIR_ITEM` or
/// `DIR_INDEX` item (names whose hashes collide share one `DIR_ITEM`). Returns false when the
/// item is malformed; the entries before the damage have been visited.
pub(crate) fn dir_entries(item: &[u8], f: &mut dyn FnMut(Key, &[u8]) -> bool) -> bool {
    let mut at = 0usize;
    while at < item.len() {
        let data_len = usize::from(le16(item, at + 25));
        let name_len = usize::from(le16(item, at + 27));
        let start = at + 30;
        let end = start + name_len;
        if name_len == 0 || name_len > NAME_MAX || end + data_len > item.len() {
            return false;
        }
        if !f(Key::parse(item, at), &item[start..end]) {
            return true;
        }
        at = end + data_len;
    }
    true
}

/// `compression` of a file extent.
pub(crate) const COMPRESS_NONE: u8 = 0;
pub(crate) const COMPRESS_ZLIB: u8 = 1;
pub(crate) const COMPRESS_LZO: u8 = 2;
pub(crate) const COMPRESS_ZSTD: u8 = 3;

/// A file extent item.
#[derive(Debug)]
pub(crate) enum Extent<'a> {
    /// Data stored in the item: `ram` bytes once decompressed.
    Inline { compression: u8, data: &'a [u8], ram: u64 },
    /// `len` bytes of file at `offset` into an extent of `ram` bytes (once decompressed)
    /// stored as `disk_len` bytes at logical `disk`; `disk` 0 is a hole.
    Regular { compression: u8, disk: u64, disk_len: u64, offset: u64, len: u64, ram: u64, prealloc: bool },
    /// Encrypted or otherwise encoded data, which no kernel writes today.
    Encoded,
}

pub(crate) fn extent(b: &[u8]) -> Option<Extent<'_>> {
    if b.len() < 21 {
        return None;
    }
    if b[17] != 0 || le16(b, 18) != 0 {
        return Some(Extent::Encoded);
    }
    let compression = b[16];
    let ram = le64(b, 8);
    match b[20] {
        0 => Some(Extent::Inline { compression, data: &b[21..], ram }),
        kind @ (1 | 2) if b.len() >= 53 => Some(Extent::Regular {
            compression,
            disk: le64(b, 21),
            disk_len: le64(b, 29),
            offset: le64(b, 37),
            len: le64(b, 45),
            ram,
            prealloc: kind == 2,
        }),
        _ => None,
    }
}

/// The fields of a root item the reader uses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RootItem {
    pub bytenr: u64,
    pub level: u8,
    pub root_dirid: u64,
    pub readonly: bool,
    pub refs: u32,
}

pub(crate) fn root_item(b: &[u8]) -> Option<RootItem> {
    (b.len() >= 239).then(|| RootItem {
        root_dirid: le64(b, 168),
        bytenr: le64(b, 176),
        readonly: le64(b, 208) & 1 != 0,
        refs: le32(b, 216),
        level: b[238],
    })
}

/// A root back reference: the directory of the parent tree that holds the subvolume, and the
/// subvolume's name there.
pub(crate) fn root_ref(b: &[u8]) -> Option<(u64, &[u8])> {
    let len = usize::from(le16(b, 16));
    Some((le64(b, 0), b.get(18..18 + len).filter(|_| len <= NAME_MAX)?))
}

/// The directory-name hash of `DIR_ITEM` keys: CRC-32C seeded with `!1`, not inverted after.
pub(crate) fn name_hash(name: &[u8]) -> u32 {
    let mut crc = !1u32;
    for &b in name {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_hashes() {
        let mut b = [0u8; 12];
        assert_eq!(time(&b, 0), None);
        b[..8].copy_from_slice(&(-1i64).to_le_bytes());
        b[8..12].copy_from_slice(&500_000_000u32.to_le_bytes());
        assert_eq!(time(&b, 0), Some(-500_000_000));
        b[8..12].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert_eq!(time(&b, 0), None);
        b[..8].copy_from_slice(&i64::MAX.to_le_bytes());
        assert_eq!(time(&b, 0), None);
        // CRC-32C check value: "123456789" with the standard seed and final inversion.
        let raw = |seed: u32, s: &[u8]| {
            let mut crc = seed;
            for &b in s {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
                }
            }
            crc
        };
        assert_eq!(!raw(!0, b"123456789"), 0xe306_9283);
        assert_eq!(name_hash(b"default"), raw(!1, b"default"));
    }

    #[test]
    fn packed_dir_entries_are_bounded() {
        let mut item = Vec::new();
        for name in [b"one".as_slice(), b"second"] {
            let mut e = vec![0u8; 30];
            e[0..8].copy_from_slice(&300u64.to_le_bytes());
            e[8] = INODE_ITEM;
            e[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes());
            item.extend_from_slice(&e);
            item.extend_from_slice(name);
        }
        let mut names = Vec::new();
        assert!(dir_entries(&item, &mut |k, n| {
            assert_eq!(k, Key::new(300, INODE_ITEM, 0));
            names.push(n.to_vec());
            true
        }));
        assert_eq!(names, [b"one".to_vec(), b"second".to_vec()]);
        // A name running past the item, and data past the item.
        let mut cut = item.clone();
        cut.truncate(item.len() - 1);
        assert!(!dir_entries(&cut, &mut |_, _| true));
        let mut long = item.clone();
        long[25..27].copy_from_slice(&1000u16.to_le_bytes());
        assert!(!dir_entries(&long, &mut |_, _| true));
    }
}

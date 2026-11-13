//! File attributes of the ZFS POSIX layer: system attributes (ZPL version 5 and later,
//! OpenZFS `sa_impl.h`, `sa.c`, `zfs_sa.h`) or the older fixed `znode_phys_t`
//! (`zfs_znode.h`).
//!
//! System attributes are a header (`sa_hdr_phys_t`: magic, layout number and header size,
//! then the lengths of the variable-size attributes) and the attributes the layout lists, in
//! order, each starting 8-byte aligned. Attribute numbers, sizes and layouts come from the
//! dataset's SA registry and layout ZAPs. What does not fit in the bonus buffer is in a spill
//! block, with a header and a layout of its own.

use std::collections::HashMap;

use super::block::{u16e, u32e, u64e, Cache, Dnode, Pool};
use super::zap;
use crate::{Error, ReadAt, Result};

const SA_MAGIC: u32 = 0x2f_505a;
pub(crate) const OT_ZNODE: u8 = 17;
pub(crate) const OT_SA: u8 = 44;
/// `sizeof(znode_phys_t)`: an old symlink's target follows it in the bonus buffer.
const ZNODE_PHYS: usize = 264;

/// The ZPL attributes the reader uses, with their sizes when no registry says otherwise.
const ATTRS: [(&str, u16); 22] = [
    ("ZPL_ATIME", 16),
    ("ZPL_MTIME", 16),
    ("ZPL_CTIME", 16),
    ("ZPL_CRTIME", 16),
    ("ZPL_GEN", 8),
    ("ZPL_MODE", 8),
    ("ZPL_SIZE", 8),
    ("ZPL_PARENT", 8),
    ("ZPL_LINKS", 8),
    ("ZPL_XATTR", 8),
    ("ZPL_RDEV", 8),
    ("ZPL_FLAGS", 8),
    ("ZPL_UID", 8),
    ("ZPL_GID", 8),
    ("ZPL_PAD", 32),
    ("ZPL_ZNODE_ACL", 88),
    ("ZPL_DACL_COUNT", 8),
    ("ZPL_SYMLINK", 0),
    ("ZPL_SCANSTAMP", 32),
    ("ZPL_DACL_ACES", 0),
    ("ZPL_DXATTR", 0),
    ("ZPL_PROJID", 8),
];

/// The attributes a node needs, by their index in [`ATTRS`].
#[derive(Clone, Copy)]
enum Attr {
    Atime = 0,
    Mtime = 1,
    Ctime = 2,
    Crtime = 3,
    Mode = 5,
    Size = 6,
    Links = 8,
    Uid = 12,
    Gid = 13,
    Symlink = 17,
}

/// Layouts and attribute numbers of one dataset.
#[derive(Default, Debug)]
pub(crate) struct Sa {
    /// Attribute number to registered length (0: variable).
    lengths: HashMap<u16, u16>,
    /// Number of each attribute of [`ATTRS`] in this dataset.
    numbers: [Option<u16>; ATTRS.len()],
    layouts: HashMap<u64, Vec<u16>>,
}

/// Most layouts and registered attributes read.
const MAX_SA_ENTRIES: usize = 4096;

impl Sa {
    /// Reads the SA master node's `REGISTRY` and `LAYOUTS` ZAPs.
    pub fn load<R: ReadAt>(
        pool: &Pool<R>,
        cache: &mut Cache,
        dnode: &dyn Fn(&mut Cache, u64) -> Result<Dnode>,
        master: u64,
    ) -> Result<Sa> {
        let mut sa = Sa::default();
        // Without a registry, attributes have their default numbers.
        for (i, (_, len)) in ATTRS.iter().enumerate() {
            sa.numbers[i] = Some(i as u16);
            sa.lengths.insert(i as u16, *len);
        }
        let node = dnode(cache, master)?;
        let (mut registry, mut layouts) = (None, None);
        zap::list(pool, cache, &node, &mut |name, v| {
            match name {
                b"REGISTRY" => registry = v.first(),
                b"LAYOUTS" => layouts = v.first(),
                _ => {}
            }
            true
        })?;
        if let Some(obj) = registry {
            let node = dnode(cache, obj)?;
            let mut count = 0;
            zap::list(pool, cache, &node, &mut |name, v| {
                count += 1;
                let Some(code) = v.first() else { return count < MAX_SA_ENTRIES };
                let (num, len) = ((code & 0xffff) as u16, (code >> 24 & 0xffff) as u16);
                sa.lengths.insert(num, len);
                if let Some(i) = ATTRS.iter().position(|(n, _)| n.as_bytes() == name) {
                    sa.numbers[i] = Some(num);
                }
                count < MAX_SA_ENTRIES
            })?;
        }
        if let Some(obj) = layouts {
            let node = dnode(cache, obj)?;
            zap::list(pool, cache, &node, &mut |name, v| {
                let id = std::str::from_utf8(name).ok().and_then(|n| n.parse::<u64>().ok());
                if let (Some(id), 2) = (id, v.int_len) {
                    sa.layouts.insert(id, v.ints().into_iter().map(|a| a as u16).collect());
                }
                sa.layouts.len() < MAX_SA_ENTRIES
            })?;
        }
        Ok(sa)
    }

    /// The attributes of one SA buffer (a bonus buffer or a spill block): each attribute
    /// number with its bytes.
    fn parse<'b>(&self, b: &'b [u8], le: bool) -> Result<Vec<(u16, &'b [u8])>> {
        let bad = |what: &str| Error::corrupt(format!("system attributes: {what}"));
        if u32e(b, 0, le) != SA_MAGIC {
            return Err(bad("no magic"));
        }
        let info = u16e(b, 4, le);
        let (layout, hdrsz) = (u64::from(info & 0x3ff), usize::from(info >> 10) * 8);
        if hdrsz < 8 || hdrsz > b.len() {
            return Err(bad("header size out of range"));
        }
        let attrs = self.layouts.get(&layout).ok_or_else(|| bad(&format!("unknown layout {layout}")))?;
        let mut out = Vec::with_capacity(attrs.len());
        let (mut at, mut var) = (hdrsz, 0usize);
        for &attr in attrs {
            let mut len = usize::from(self.lengths.get(&attr).copied().unwrap_or(0));
            if len == 0 {
                let slot = 6 + 2 * var;
                if slot + 2 > hdrsz {
                    return Err(bad("more variable-size attributes than lengths"));
                }
                len = usize::from(u16e(b, slot, le));
                var += 1;
            }
            let data = b.get(at..at + len).ok_or_else(|| bad("attribute past the end of its buffer"))?;
            out.push((attr, data));
            at += len.next_multiple_of(8);
        }
        Ok(out)
    }
}

/// A file's attributes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Znode {
    pub mode: u64,
    pub size: u64,
    pub uid: u64,
    pub gid: u64,
    pub links: u64,
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub crtime: Option<i64>,
    /// A symlink target kept with the attributes; `None` when it is in the object's data.
    pub symlink: Option<Vec<u8>>,
}

/// A `[seconds, nanoseconds]` time as nanoseconds since the epoch; zero is no time.
fn time(b: &[u8], le: bool) -> Option<i64> {
    let (sec, nsec) = (u64e(b, 0, le) as i64, u64e(b, 8, le) as i64);
    if sec == 0 && nsec == 0 {
        return None;
    }
    sec.checked_mul(1_000_000_000).and_then(|t| t.checked_add(nsec.clamp(0, 999_999_999)))
}

/// The attributes of the object `dn`, from its bonus buffer and spill block.
pub(crate) fn znode<R: ReadAt>(pool: &Pool<R>, cache: &mut Cache, sa: Option<&Sa>, dn: &Dnode) -> Result<Znode> {
    match (dn.bonustype, sa) {
        (OT_SA, Some(sa)) => {
            let mut z = Znode::default();
            let mut found = [false; ATTRS.len()];
            let mut fill = |attrs: Vec<(u16, &[u8])>, le: bool| {
                for (num, data) in attrs {
                    let Some(i) = sa.numbers.iter().position(|n| *n == Some(num)) else { continue };
                    if found[i] {
                        continue;
                    }
                    found[i] = true;
                    let v = u64e(data, 0, le);
                    match i {
                        i if i == Attr::Mode as usize => z.mode = v,
                        i if i == Attr::Size as usize => z.size = v,
                        i if i == Attr::Uid as usize => z.uid = v,
                        i if i == Attr::Gid as usize => z.gid = v,
                        i if i == Attr::Links as usize => z.links = v,
                        i if i == Attr::Atime as usize => z.atime = time(data, le),
                        i if i == Attr::Mtime as usize => z.mtime = time(data, le),
                        i if i == Attr::Ctime as usize => z.ctime = time(data, le),
                        i if i == Attr::Crtime as usize => z.crtime = time(data, le),
                        i if i == Attr::Symlink as usize => z.symlink = Some(data.to_vec()),
                        _ => {}
                    }
                }
            };
            fill(sa.parse(&dn.bonus, dn.le)?, dn.le);
            if let Some(bp) = dn.spill.filter(|bp| !bp.hole()) {
                let block = pool.read(cache, &bp)?;
                fill(sa.parse(&block.data, block.le)?, block.le);
            }
            if !found[Attr::Mode as usize] || !found[Attr::Size as usize] {
                return Err(Error::corrupt("system attributes without a mode or size"));
            }
            Ok(z)
        }
        (OT_SA, None) => Err(Error::corrupt("system attributes in a dataset without an SA registry")),
        (OT_ZNODE, _) => {
            let (b, le) = (&dn.bonus, dn.le);
            if b.len() < ZNODE_PHYS {
                return Err(Error::corrupt("znode bonus buffer too short"));
            }
            let size = u64e(b, 80, le);
            let inline = usize::try_from(size).ok().and_then(|n| b.get(ZNODE_PHYS..ZNODE_PHYS.checked_add(n)?));
            Ok(Znode {
                atime: time(&b[0..16], le),
                mtime: time(&b[16..32], le),
                ctime: time(&b[32..48], le),
                crtime: time(&b[48..64], le),
                mode: u64e(b, 72, le),
                size,
                links: u64e(b, 96, le),
                uid: u64e(b, 128, le),
                gid: u64e(b, 136, le),
                symlink: inline.map(<[u8]>::to_vec),
            })
        }
        (t, _) => Err(Error::corrupt(format!("bonus buffer of type {t} is not a file's attributes"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_attributes_are_aligned() {
        let mut sa = Sa::default();
        sa.lengths.extend([(5, 8), (6, 8), (17, 0), (19, 0)]);
        sa.layouts.insert(3, vec![5, 19, 17, 6]);
        // Header: magic, layout 3 with a 16-byte header, lengths 12 and 5.
        let mut b = Vec::new();
        b.extend_from_slice(&SA_MAGIC.to_le_bytes());
        b.extend_from_slice(&(3u16 | 2 << 10).to_le_bytes());
        b.extend_from_slice(&12u16.to_le_bytes());
        b.extend_from_slice(&5u16.to_le_bytes());
        b.extend_from_slice(&[0; 6]);
        b.extend_from_slice(&0o100644u64.to_le_bytes());
        b.extend_from_slice(&[1; 12]);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(b"hello\0\0\0");
        b.extend_from_slice(&42u64.to_le_bytes());
        let attrs = sa.parse(&b, true).unwrap();
        assert_eq!(attrs.len(), 4);
        assert_eq!(attrs[2], (17, &b"hello"[..]));
        assert_eq!(u64e(attrs[3].1, 0, true), 42);
        // Truncated, another layout, too many variable lengths for the header.
        assert!(sa.parse(&b[..40], true).is_err());
        let mut other = b.clone();
        other[4] = 4;
        assert!(sa.parse(&other, true).is_err());
        let mut short = b.clone();
        short[5] = 1 << 2;
        assert!(sa.parse(&short, true).is_err());
        assert!(sa.parse(&b, false).is_err());
    }

    #[test]
    fn times() {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&(-1i64).to_le_bytes());
        b[8..].copy_from_slice(&500_000_000u64.to_le_bytes());
        assert_eq!(time(&b, true), Some(-500_000_000));
        assert_eq!(time(&[0; 16], true), None);
        b[..8].copy_from_slice(&i64::MAX.to_le_bytes());
        assert_eq!(time(&b, true), None);
    }
}

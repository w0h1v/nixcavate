//! Vdev labels: the XDR-encoded name-value list that describes the pool and this device, and
//! the uberblock ring (OpenZFS `vdev_impl.h` `vdev_label_t`, `uberblock_impl.h`,
//! `module/nvpair/nvpair.c` `nvs_xdr_*`).
//!
//! A device has four 256 KiB labels, two at its start and two at its end. Each holds the
//! name-value list at 16 KiB and the uberblock ring at 128 KiB: slots of `2^ashift` bytes
//! (at least 1 KiB, at most 8 KiB), each an uberblock written at some transaction group.

use crate::{be32, be64, le64, ReadAt};

pub(crate) const LABEL_SIZE: u64 = 256 << 10;
const NVLIST_AT: u64 = 16 << 10;
/// The name-value list area, less the embedded checksum at its end.
const NVLIST_SIZE: usize = (112 << 10) - 40;
const RING_AT: u64 = 128 << 10;
const RING_SIZE: usize = 128 << 10;
pub(crate) const UB_MAGIC: u64 = 0x00ba_b10c;

/// Nesting accepted in a name-value list (the vdev tree is three or four deep).
const MAX_NV_DEPTH: usize = 16;
/// Pairs accepted in one list, and elements in one array.
const MAX_NV_PAIRS: usize = 4096;
const MAX_NV_ARRAY: usize = 4096;

/// A decoded value. Types the reader never uses are kept as `Other`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    U64(u64),
    Str(String),
    List(NvList),
    Lists(Vec<NvList>),
    Bool(bool),
    Other,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct NvList(pub Vec<(String, Value)>);

impl NvList {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn u64(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(Value::U64(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn list(&self, name: &str) -> Option<&NvList> {
        match self.get(name) {
            Some(Value::List(l)) => Some(l),
            _ => None,
        }
    }

    pub fn lists(&self, name: &str) -> &[NvList] {
        match self.get(name) {
            Some(Value::Lists(l)) => l,
            _ => &[],
        }
    }
}

/// XDR data types (`data_type_t`).
const BOOLEAN: u32 = 1;
const UINT64: u32 = 8;
const STRING: u32 = 9;
const NVLIST: u32 = 19;
const NVLIST_ARRAY: u32 = 20;
const BOOLEAN_VALUE: u32 = 21;

struct Xdr<'a> {
    b: &'a [u8],
    at: usize,
}

impl Xdr<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = self.b.get(self.at..self.at + 4).map(|s| be32(s, 0))?;
        self.at += 4;
        Some(v)
    }

    fn u64(&mut self) -> Option<u64> {
        let v = self.b.get(self.at..self.at + 8).map(|s| be64(s, 0))?;
        self.at += 8;
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let s = self.b.get(self.at..self.at.checked_add(len)?)?;
        self.at += len.next_multiple_of(4);
        Some(String::from_utf8_lossy(s).into_owned())
    }

    /// One list: version and flags, then pairs until a pair of zero size.
    fn list(&mut self, depth: usize) -> Option<NvList> {
        if depth > MAX_NV_DEPTH {
            return None;
        }
        let _version = self.u32()?;
        let _flags = self.u32()?;
        let mut out = NvList::default();
        loop {
            let start = self.at;
            let encoded = self.u32()? as usize;
            let _decoded = self.u32()?;
            if encoded == 0 {
                return Some(out);
            }
            if out.0.len() >= MAX_NV_PAIRS {
                return None;
            }
            let end = start.checked_add(encoded).filter(|&e| e <= self.b.len())?;
            let name = self.string()?;
            let kind = self.u32()?;
            let count = self.u32()? as usize;
            let value = match kind {
                UINT64 if count == 1 => Value::U64(self.u64()?),
                STRING if count == 1 => Value::Str(self.string()?),
                BOOLEAN => Value::Bool(true),
                BOOLEAN_VALUE if count == 1 => Value::Bool(self.u32()? != 0),
                // A nested list follows the pair header and is read in place.
                NVLIST if count == 1 => {
                    let list = self.list(depth + 1)?;
                    out.0.push((name, Value::List(list)));
                    continue;
                }
                NVLIST_ARRAY => {
                    if count > MAX_NV_ARRAY {
                        return None;
                    }
                    let mut lists = Vec::new();
                    for _ in 0..count {
                        lists.push(self.list(depth + 1)?);
                    }
                    out.0.push((name, Value::Lists(lists)));
                    continue;
                }
                _ => Value::Other,
            };
            self.at = end;
            out.0.push((name, value));
        }
    }
}

/// Decodes a packed name-value list (`nvlist_unpack`): a 4-byte header naming the encoding,
/// then the list. Only XDR, the encoding labels and the pool configuration use, is read.
pub(crate) fn unpack(b: &[u8]) -> Option<NvList> {
    if b.first() != Some(&1) {
        return None;
    }
    Xdr { b, at: 4 }.list(0)
}

/// Where label `n` (0 to 3) of a device of `size` bytes starts.
pub(crate) fn label_offset(size: u64, n: u64) -> Option<u64> {
    let aligned = size / LABEL_SIZE * LABEL_SIZE;
    if aligned < 4 * LABEL_SIZE {
        return None;
    }
    Some(if n < 2 { n * LABEL_SIZE } else { aligned - (4 - n) * LABEL_SIZE })
}

/// The name-value list of label `n` of `dev`.
pub(crate) fn read_config(dev: &dyn ReadAt, n: u64) -> Option<NvList> {
    let at = label_offset(dev.size(), n)?;
    let mut buf = vec![0u8; NVLIST_SIZE];
    dev.read_at(at + NVLIST_AT, &mut buf).ok()?;
    unpack(&buf)
}

/// The first readable label's configuration.
pub(crate) fn config(dev: &dyn ReadAt) -> Option<NvList> {
    (0..4).find_map(|n| read_config(dev, n))
}

/// Whether `dev` starts with a ZFS label: an XDR name-value list at 16 KiB of label 0 or 1,
/// and an uberblock in its ring.
pub(crate) fn probe(dev: &dyn ReadAt) -> bool {
    for n in 0..2u64 {
        let base = n * LABEL_SIZE;
        let mut head = [0u8; 12];
        if dev.read_at(base + NVLIST_AT, &mut head).is_err() || head[..2] != [1, 1] && head[..2] != [1, 0] {
            continue;
        }
        // XDR version 0, flags NV_UNIQUE_NAME (1).
        if be32(&head, 4) != 0 || be32(&head, 8) != 1 {
            continue;
        }
        let mut ring = vec![0u8; RING_SIZE];
        if dev.read_at(base + RING_AT, &mut ring).is_err() {
            continue;
        }
        let found = ring.chunks_exact(1024).any(|s| {
            let m = le64(s, 0);
            m == UB_MAGIC || m == UB_MAGIC.swap_bytes()
        });
        if found {
            return true;
        }
    }
    false
}

/// One uberblock: the root of the pool at transaction group `txg`.
#[derive(Clone, Debug)]
pub(crate) struct Uberblock {
    pub txg: u64,
    pub timestamp: u64,
    pub version: u64,
    /// The root block pointer (128 bytes, in the uberblock's byte order).
    pub rootbp: [u8; 128],
    pub le: bool,
}

/// Parses one ring slot.
pub(crate) fn uberblock(slot: &[u8]) -> Option<Uberblock> {
    let magic = le64(slot, 0);
    let le = match magic {
        UB_MAGIC => true,
        m if m == UB_MAGIC.swap_bytes() => false,
        _ => return None,
    };
    let get = |at: usize| if le { le64(slot, at) } else { be64(slot, at) };
    let rootbp: [u8; 128] = crate::array(slot, 40);
    Some(Uberblock { txg: get(16), timestamp: get(32), version: get(8), rootbp, le })
}

/// Every uberblock in the rings of the four labels, best (highest transaction group, then
/// latest time) first. `ashift` gives the slot size.
pub(crate) fn uberblocks(dev: &dyn ReadAt, ashift: u64) -> Vec<Uberblock> {
    let slot = 1usize << ashift.clamp(10, 13);
    let mut out = Vec::new();
    for n in 0..4 {
        let Some(at) = label_offset(dev.size(), n) else { continue };
        let mut ring = vec![0u8; RING_SIZE];
        if dev.read_at(at + RING_AT, &mut ring).is_err() {
            continue;
        }
        out.extend(ring.chunks_exact(slot).filter_map(uberblock));
    }
    out.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An XDR encoder for tests.
    pub(crate) struct Enc(pub Vec<u8>);

    type Body = Box<dyn FnOnce(&mut Enc)>;

    impl Enc {
        pub fn new() -> Enc {
            Enc(vec![1, 1, 0, 0])
        }

        fn s(&mut self, s: &str) {
            self.0.extend_from_slice(&(s.len() as u32).to_be_bytes());
            self.0.extend_from_slice(s.as_bytes());
            self.0.resize(self.0.len().next_multiple_of(4), 0);
        }

        pub fn begin(&mut self) {
            self.0.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        }

        pub fn end(&mut self) {
            self.0.extend_from_slice(&[0; 8]);
        }

        /// A pair header; returns where its size goes.
        fn pair(&mut self, name: &str, kind: u32, count: u32) -> usize {
            let at = self.0.len();
            self.0.extend_from_slice(&[0; 8]);
            self.s(name);
            self.0.extend_from_slice(&kind.to_be_bytes());
            self.0.extend_from_slice(&count.to_be_bytes());
            at
        }

        fn close(&mut self, at: usize) {
            let size = (self.0.len() - at) as u32;
            self.0[at..at + 4].copy_from_slice(&size.to_be_bytes());
            self.0[at + 4..at + 8].copy_from_slice(&size.to_be_bytes());
        }

        pub fn u64(&mut self, name: &str, v: u64) {
            let at = self.pair(name, UINT64, 1);
            self.0.extend_from_slice(&v.to_be_bytes());
            self.close(at);
        }

        pub fn str(&mut self, name: &str, v: &str) {
            let at = self.pair(name, STRING, 1);
            self.s(v);
            self.close(at);
        }

        pub fn list(&mut self, name: &str, body: impl FnOnce(&mut Enc)) {
            // The pair's size counts the nested list, as `nvs_xdr_nvp_size` does.
            let at = self.pair(name, NVLIST, 1);
            self.begin();
            body(self);
            self.end();
            self.close(at);
        }

        pub fn lists(&mut self, name: &str, bodies: Vec<Body>) {
            let at = self.pair(name, NVLIST_ARRAY, bodies.len() as u32);
            for body in bodies {
                self.begin();
                body(self);
                self.end();
            }
            self.close(at);
        }
    }

    #[test]
    fn decodes_nested_lists() {
        let mut e = Enc::new();
        e.begin();
        e.u64("version", 5000);
        e.str("name", "tank");
        e.list("vdev_tree", |e| {
            e.str("type", "mirror");
            e.lists(
                "children",
                vec![Box::new(|e: &mut Enc| e.u64("guid", 1)), Box::new(|e: &mut Enc| e.u64("guid", 2))],
            );
        });
        e.list("features_for_read", |e| {
            let at = e.pair("com.delphix:hole_birth", BOOLEAN, 0);
            e.close(at);
        });
        e.u64("after", 7);
        e.end();
        let nv = unpack(&e.0).unwrap();
        assert_eq!(nv.u64("version"), Some(5000));
        assert_eq!(nv.str("name"), Some("tank"));
        let tree = nv.list("vdev_tree").unwrap();
        assert_eq!(tree.lists("children").iter().map(|c| c.u64("guid").unwrap()).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(nv.list("features_for_read").unwrap().0[0].0, "com.delphix:hole_birth");
        assert_eq!(nv.u64("after"), Some(7));
        // Every truncation fails or decodes less, without panicking.
        for n in 0..e.0.len() {
            let _ = unpack(&e.0[..n]);
        }
    }

    #[test]
    fn refuses_deep_and_huge_lists() {
        let mut e = Enc::new();
        e.begin();
        fn nest(e: &mut Enc, n: usize) {
            if n > 0 {
                e.list("x", |e| nest(e, n - 1));
            }
        }
        nest(&mut e, 40);
        e.end();
        assert!(unpack(&e.0).is_none());
        let mut e = Enc::new();
        e.begin();
        let at = e.pair("many", NVLIST_ARRAY, u32::MAX);
        e.close(at);
        assert!(unpack(&e.0).is_none());
    }

    #[test]
    fn label_offsets() {
        let size = 64 << 20;
        assert_eq!(label_offset(size, 0), Some(0));
        assert_eq!(label_offset(size, 1), Some(256 << 10));
        assert_eq!(label_offset(size, 2), Some(size - (512 << 10)));
        assert_eq!(label_offset(size + 1000, 3), Some(size - (256 << 10)));
        assert_eq!(label_offset(1 << 19, 0), None);
    }
}

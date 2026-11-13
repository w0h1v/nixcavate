//! Block pointers, the vdev tree that maps them to device offsets, and dnodes: reading one
//! logical block of an object (OpenZFS `spa.h`, `vdev_raidz.c` `vdev_raidz_map_alloc`,
//! `zio.c` gang blocks, `dnode.h`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::compress;
use crate::btrfs::{Compression, Decompress};
use crate::{be64, le64, Error, ReadAt, Result};

/// Data starts after the two front labels and the 3.5 MiB boot area of every leaf device.
pub(crate) const LABEL_START: u64 = 4 << 20;
/// The largest block (`SPA_MAXBLOCKSIZE`, the `large_blocks` feature).
pub(crate) const MAX_BLOCK: u64 = 16 << 20;
const GANG_SIZE: usize = 512;
/// Gang headers nested in gang headers that one read follows.
const MAX_GANG_DEPTH: usize = 4;
/// Levels of an object's block tree (`DN_MAX_LEVELS` with 4 KiB indirect blocks).
pub(crate) const MAX_LEVELS: u8 = 12;
/// Bytes of decoded blocks one operation keeps before its cache is dropped and refilled.
const CACHE_BYTES: usize = 128 << 20;
/// Bytes of indirect and dnode blocks kept across operations: every file read starts with
/// the same few blocks of the meta dnode's tree (six levels of 128 KiB blocks, usually).
const SHARED_BYTES: usize = 64 << 20;
const OT_DNODE: u64 = 10;
const OT_PLAIN_FILE: u64 = 19;
/// Block reads (cache hits included) one operation may make.
const FETCH_BUDGET: u64 = crate::MAX_NODES * 64;
/// Bytes one operation may decompress or read from the devices before it stops: a walk of
/// the largest volume reads a small part of this; a crafted pool that sends every lookup
/// through 16 MiB blocks stops.
const BYTE_BUDGET: u64 = 1 << 40;

/// Integers at `at` in the given byte order.
pub(crate) fn u64e(b: &[u8], at: usize, le: bool) -> u64 {
    if le {
        le64(b, at)
    } else {
        be64(b, at)
    }
}

pub(crate) fn u32e(b: &[u8], at: usize, le: bool) -> u32 {
    if le {
        crate::le32(b, at)
    } else {
        crate::be32(b, at)
    }
}

pub(crate) fn u16e(b: &[u8], at: usize, le: bool) -> u16 {
    if le {
        crate::le16(b, at)
    } else {
        crate::be16(b, at)
    }
}

/// A block pointer (`blkptr_t`, 128 bytes), as words in host order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bp {
    words: [u64; 16],
}

/// Compression values of a block pointer (`zio_compress`).
const COMPRESS_OFF: u64 = 2;
const COMPRESS_LZJB: u64 = 3;
const COMPRESS_EMPTY: u64 = 4;
const COMPRESS_GZIP_1: u64 = 5;
const COMPRESS_GZIP_9: u64 = 13;
const COMPRESS_ZLE: u64 = 14;
const COMPRESS_LZ4: u64 = 15;
const COMPRESS_ZSTD: u64 = 16;

pub(crate) const OT_OBJSET: u64 = 11;

impl Bp {
    /// The block pointer at `at` of a block in byte order `le`; zeros past the end.
    pub fn parse(b: &[u8], at: usize, le: bool) -> Bp {
        let mut words = [0u64; 16];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u64e(b, at.wrapping_add(i * 8), le);
        }
        Bp { words }
    }

    fn prop(&self) -> u64 {
        self.words[6]
    }

    pub fn embedded(&self) -> bool {
        self.prop() >> 39 & 1 != 0
    }

    pub fn hole(&self) -> bool {
        !self.embedded() && self.words[0] == 0 && self.words[1] == 0
    }

    pub fn lsize(&self) -> u64 {
        if self.embedded() {
            (self.prop() & 0x1ff_ffff) + 1
        } else {
            ((self.prop() & 0xffff) + 1) << 9
        }
    }

    pub fn psize(&self) -> u64 {
        if self.embedded() {
            (self.prop() >> 25 & 0x7f) + 1
        } else {
            ((self.prop() >> 16 & 0xffff) + 1) << 9
        }
    }

    fn compression(&self) -> u64 {
        self.prop() >> 32 & 0x7f
    }

    pub fn checksum(&self) -> u64 {
        self.prop() >> 40 & 0xff
    }

    /// The checksum (for an intent log block, the verifier that chains its blocks).
    pub fn cksum(&self) -> [u64; 4] {
        [self.words[12], self.words[13], self.words[14], self.words[15]]
    }

    pub fn kind(&self) -> u64 {
        self.prop() >> 48 & 0xff
    }

    pub fn level(&self) -> u8 {
        (self.prop() >> 56 & 0x1f) as u8
    }

    /// Native encryption: the block is encrypted or authenticated.
    pub fn crypt(&self) -> bool {
        self.prop() >> 61 & 1 != 0
    }

    /// The byte order of the block it points to.
    pub fn little_endian(&self) -> bool {
        self.prop() >> 63 != 0
    }

    pub fn birth(&self) -> u64 {
        self.words[10]
    }

    /// The `n`th address: top-level vdev, offset in it, allocated size, gang bit. `None` when
    /// empty. An encrypted block keeps its salt and IV where the third address would be.
    pub fn dva(&self, n: usize) -> Option<Dva> {
        if n > 2 || self.embedded() || (n == 2 && self.crypt()) {
            return None;
        }
        let (w0, w1) = (self.words[2 * n], self.words[2 * n + 1]);
        if w0 == 0 && w1 == 0 {
            return None;
        }
        let offset = (w1 & !(1 << 63)).checked_mul(512)?;
        Some(Dva { vdev: w0 >> 32, offset, asize: (w0 & 0xff_ffff) << 9, gang: w1 >> 63 != 0 })
    }

    /// The payload of an embedded block pointer: every word but the properties and the
    /// logical birth, least significant byte first.
    fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(112);
        for (i, w) in self.words.iter().enumerate() {
            if i != 6 && i != 10 {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        out.truncate(self.psize() as usize);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Dva {
    pub vdev: u64,
    pub offset: u64,
    pub asize: u64,
    pub gang: bool,
}

/// A vdev, as the label's tree describes it.
#[derive(Clone, Debug)]
pub(crate) enum Vdev {
    /// A disk or file: the index of the device the caller gave, when it is present.
    Leaf {
        guid: u64,
        dev: Option<usize>,
    },
    /// A mirror (or a replacing or spare vdev): every child holds the whole copy.
    Mirror(Vec<Vdev>),
    RaidZ {
        nparity: u64,
        ashift: u64,
        children: Vec<Vdev>,
    },
    /// Anything else: dRAID, an indirect (removed) vdev, a hole. Reads fail with the reason.
    Unreadable(String),
}

impl Vdev {
    /// Leaf guids this vdev needs that are absent.
    pub fn missing(&self, out: &mut Vec<u64>) {
        match self {
            Vdev::Leaf { guid, dev: None } => out.push(*guid),
            Vdev::Leaf { .. } | Vdev::Unreadable(_) => {}
            Vdev::Mirror(c) => {
                let mut inner = Vec::new();
                for child in c {
                    child.missing(&mut inner);
                }
                // A mirror needs only one present child.
                if c.iter().all(|child| {
                    let mut m = Vec::new();
                    child.missing(&mut m);
                    !m.is_empty()
                }) {
                    out.extend(inner);
                }
            }
            Vdev::RaidZ { children, .. } => {
                for child in children {
                    child.missing(out);
                }
            }
        }
    }
}

/// One decoded logical block and the byte order of its contents.
pub(crate) struct Block {
    pub data: Vec<u8>,
    pub le: bool,
}

/// Per-operation state: decoded blocks and a work budget that stops a looping or absurdly
/// large structure.
pub(crate) struct Cache {
    blocks: HashMap<(u64, u64, u64), Arc<Block>>,
    bytes: usize,
    budget: u64,
    bytes_left: u64,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { blocks: HashMap::new(), bytes: 0, budget: FETCH_BUDGET, bytes_left: BYTE_BUDGET }
    }

    pub fn exhausted(&self) -> bool {
        self.budget == 0 || self.bytes_left == 0
    }

    fn keep(&mut self, key: (u64, u64, u64), block: Arc<Block>) {
        if self.bytes + block.data.len() > CACHE_BYTES {
            self.blocks.clear();
            self.bytes = 0;
        }
        self.bytes += block.data.len();
        self.blocks.insert(key, block);
    }

    fn spend(&mut self, bytes: u64) -> Result<()> {
        self.budget = self.budget.checked_sub(1).ok_or_else(|| Error::corrupt("block reads exceeded their budget"))?;
        self.bytes_left = self
            .bytes_left
            .checked_sub(bytes)
            .ok_or_else(|| Error::corrupt("block reads exceeded their byte budget"))?;
        Ok(())
    }
}

/// Decoded blocks shared by every operation.
#[derive(Default)]
pub(crate) struct Shared {
    blocks: HashMap<(u64, u64, u64), Arc<Block>>,
    bytes: usize,
}

/// What blocks are read with: the devices, the top-level vdevs, the decompressor.
pub(crate) struct Pool<R> {
    pub devices: Vec<R>,
    /// Top-level vdevs by id; `None` for one no label describes.
    pub top: Vec<Option<Vdev>>,
    pub decompress: Option<Box<dyn Decompress + Send>>,
    pub shared: Mutex<Shared>,
}

impl<R: ReadAt> Pool<R> {
    /// Reads `buf.len()` bytes at `offset` of `vdev`.
    fn read_vdev(&self, vdev: &Vdev, offset: u64, buf: &mut [u8]) -> Result<()> {
        match vdev {
            Vdev::Leaf { dev: Some(i), .. } => {
                let dev = &self.devices[*i];
                let at = offset.checked_add(LABEL_START).ok_or_else(|| Error::corrupt("offset overflows"))?;
                if at.checked_add(buf.len() as u64).is_none_or(|end| end > dev.size()) {
                    return Err(Error::corrupt(format!("block at {offset:#x} is past the end of its device")));
                }
                Ok(dev.read_at(at, buf)?)
            }
            Vdev::Leaf { guid, dev: None } => Err(Error::unsupported(format!("vdev {guid} is not in the image"))),
            Vdev::Mirror(children) => {
                let mut first = None;
                for child in children {
                    match self.read_vdev(child, offset, buf) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            first.get_or_insert(e);
                        }
                    }
                }
                Err(first.unwrap_or_else(|| Error::corrupt("mirror with no children")))
            }
            Vdev::RaidZ { nparity, ashift, children } => {
                let columns = raidz_columns(offset, buf.len() as u64, *nparity, *ashift, children.len() as u64)?;
                let mut done = 0usize;
                for (dev, at, size) in columns {
                    let size = size as usize;
                    let end = (done + size).min(buf.len());
                    if done < end {
                        self.read_vdev(&children[dev as usize], at, &mut buf[done..end])?;
                    }
                    done = end;
                }
                Ok(())
            }
            Vdev::Unreadable(why) => Err(Error::unsupported(why.clone())),
        }
    }

    /// The physical bytes of one address: `size` bytes, through a gang header if it is one.
    fn read_dva(&self, cache: &mut Cache, dva: Dva, size: u64, depth: usize) -> Result<Vec<u8>> {
        let top = self.top.get(dva.vdev as usize).and_then(Option::as_ref);
        let top = top.ok_or_else(|| Error::unsupported(format!("top-level vdev {} is not in the image", dva.vdev)))?;
        if !dva.gang {
            let mut buf = vec![0u8; size as usize];
            self.read_vdev(top, dva.offset, &mut buf)?;
            return Ok(buf);
        }
        // A gang header: three block pointers whose blocks, in order, hold the data.
        if depth >= MAX_GANG_DEPTH {
            return Err(Error::corrupt("gang blocks nested too deep"));
        }
        let mut header = vec![0u8; GANG_SIZE];
        self.read_vdev(top, dva.offset, &mut header)?;
        // The embedded checksum's magic at the end says the byte order.
        let le = match le64(&header, GANG_SIZE - 40) {
            0x0210_da7a_b10c_7a11 => true,
            m if m == 0x0210_da7a_b10c_7a11u64.swap_bytes() => false,
            _ => return Err(Error::corrupt("gang header without its magic")),
        };
        let mut out = Vec::with_capacity(size as usize);
        for i in 0..3 {
            if out.len() as u64 >= size {
                break;
            }
            let bp = Bp::parse(&header, i * 128, le);
            if bp.hole() {
                continue;
            }
            let part = self.physical(cache, &bp, depth + 1)?;
            out.extend_from_slice(&part);
        }
        if (out.len() as u64) < size {
            return Err(Error::corrupt("gang block shorter than its block"));
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// The physical (still compressed) bytes of a block, from the first address that reads.
    fn physical(&self, cache: &mut Cache, bp: &Bp, depth: usize) -> Result<Vec<u8>> {
        let psize = bp.psize();
        if psize > MAX_BLOCK {
            return Err(Error::corrupt(format!("block of {psize} bytes")));
        }
        cache.spend(psize)?;
        let mut first = None;
        for n in 0..3 {
            let Some(dva) = bp.dva(n) else { continue };
            match self.read_dva(cache, dva, psize, depth) {
                Ok(data) => return Ok(data),
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        Err(first.unwrap_or_else(|| Error::corrupt("block pointer with no address")))
    }

    /// The logical contents of the block `bp` points to.
    pub fn read(&self, cache: &mut Cache, bp: &Bp) -> Result<Arc<Block>> {
        let (lsize, psize) = (bp.lsize(), bp.psize());
        if lsize > MAX_BLOCK || psize > MAX_BLOCK || (bp.compression() != COMPRESS_OFF && psize > lsize) {
            return Err(Error::corrupt(format!("block of {lsize} bytes stored in {psize}")));
        }
        let le = bp.little_endian();
        if bp.hole() {
            cache.spend(lsize)?;
            return Ok(Arc::new(Block { data: vec![0; lsize as usize], le }));
        }
        if bp.crypt() && bp.level() == 0 && bp.kind() != OT_OBJSET {
            return Err(Error::unsupported("encrypted block (native encryption)"));
        }
        let key = bp.dva(0).map(|d| (d.vdev, d.offset, bp.birth()));
        if let Some(block) = key.and_then(|k| cache.blocks.get(&k)) {
            let block = block.clone();
            cache.spend(0)?;
            return Ok(block);
        }
        let shareable = bp.level() > 0 || bp.kind() == OT_DNODE;
        if let (true, Some(k)) = (shareable, key) {
            let found = self.shared().blocks.get(&k).cloned();
            if let Some(block) = found {
                cache.spend(0)?;
                cache.keep(k, block.clone());
                return Ok(block);
            }
        }
        let raw = if bp.embedded() {
            // Only the data form (type 0) holds data; a redacted block has none.
            let etype = bp.prop() >> 40 & 0xff;
            if etype != 0 {
                return Err(Error::unsupported(format!("embedded block pointer of type {etype}")));
            }
            cache.spend(psize)?;
            bp.payload()
        } else {
            self.physical(cache, bp, 0)?
        };
        cache.spend(lsize)?;
        let data = self.decompress(bp.compression(), &raw, lsize as usize)?;
        let block = Arc::new(Block { data, le });
        // File data is read once: keeping it would only hold memory.
        let file_data = bp.level() == 0 && bp.kind() == OT_PLAIN_FILE;
        if let (Some(key), false) = (key, file_data) {
            cache.keep(key, block.clone());
            if shareable {
                let mut shared = self.shared();
                if shared.bytes + block.data.len() > SHARED_BYTES {
                    shared.blocks.clear();
                    shared.bytes = 0;
                }
                shared.bytes += block.data.len();
                shared.blocks.insert(key, block.clone());
            }
        }
        Ok(block)
    }

    fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        // A panic elsewhere cannot leave the map inconsistent: every update is one insert.
        match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn decompress(&self, compression: u64, raw: &[u8], lsize: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; lsize];
        let hook = |kind: Compression, input: &[u8], out: &mut Vec<u8>| -> Result<()> {
            let mut got = Vec::new();
            match &self.decompress {
                Some(d) => d.decompress(kind, input, &mut got, lsize)?,
                None => return Err(Error::unsupported(format!("{kind:?}-compressed block: no decompressor"))),
            }
            if got.len() != lsize {
                return Err(Error::corrupt(format!("{kind:?} block decompressed to {} of {lsize} bytes", got.len())));
            }
            *out = got;
            Ok(())
        };
        match compression {
            COMPRESS_OFF => {
                let n = raw.len().min(lsize);
                out[..n].copy_from_slice(&raw[..n]);
            }
            COMPRESS_EMPTY => {}
            COMPRESS_LZ4 => compress::lz4_zfs(raw, &mut out)?,
            COMPRESS_LZJB => compress::lzjb(raw, &mut out)?,
            COMPRESS_ZLE => compress::zle(raw, &mut out)?,
            COMPRESS_GZIP_1..=COMPRESS_GZIP_9 => hook(Compression::Zlib, raw, &mut out)?,
            COMPRESS_ZSTD => {
                // A big-endian compressed length and a version-and-level word, then a zstd
                // frame written without its magic number.
                let len = crate::be32(raw, 0) as usize;
                let frame =
                    raw.get(8..).and_then(|f| f.get(..len)).ok_or_else(|| Error::corrupt("zstd block length"))?;
                let mut input = Vec::with_capacity(len + 4);
                input.extend_from_slice(&0xfd2f_b528u32.to_le_bytes());
                input.extend_from_slice(frame);
                hook(Compression::Zstd, &input, &mut out)?;
            }
            c => return Err(Error::unsupported(format!("compression type {c}"))),
        }
        Ok(out)
    }
}

/// The columns of a RAID-Z block (`vdev_raidz_map_alloc`, before RAID-Z expansion): for
/// each data column in order, the child, the offset in it and the bytes it holds. Parity
/// columns are skipped: nothing is reconstructed.
pub(crate) fn raidz_columns(
    offset: u64,
    size: u64,
    nparity: u64,
    ashift: u64,
    dcols: u64,
) -> Result<Vec<(u64, u64, u64)>> {
    if !(1..=3).contains(&nparity) || dcols <= nparity || dcols > 255 || !(9..=16).contains(&ashift) {
        return Err(Error::corrupt("RAID-Z geometry out of range"));
    }
    let unit = 1u64 << ashift;
    // The block's sectors: its size rounded up to whole sectors, as the I/O is.
    let s = size.div_ceil(unit);
    let b = offset >> ashift;
    let f = b % dcols;
    let o = (b / dcols) << ashift;
    let q = s / (dcols - nparity);
    let r = s - q * (dcols - nparity);
    let bc = if r == 0 { 0 } else { r + nparity };
    let (acols, scols) = if q == 0 { (bc, dcols.min(bc.next_multiple_of(nparity + 1))) } else { (dcols, dcols) };
    let mut cols = Vec::with_capacity(scols as usize);
    for c in 0..scols {
        let mut col = f + c;
        let mut coff = o;
        if col >= dcols {
            col -= dcols;
            coff += unit;
        }
        let rows = if c >= acols {
            0
        } else if c < bc {
            q + 1
        } else {
            q
        };
        cols.push((col, coff, rows << ashift));
    }
    // Single parity moves to the second column every other MiB.
    if nparity == 1 && offset & (1 << 20) != 0 && cols.len() >= 2 {
        let (d0, o0) = (cols[0].0, cols[0].1);
        (cols[0].0, cols[0].1) = (cols[1].0, cols[1].1);
        (cols[1].0, cols[1].1) = (d0, o0);
    }
    Ok(cols.into_iter().skip(nparity as usize).take((acols.saturating_sub(nparity)) as usize).collect())
}

/// A dnode (`dnode_phys_t`): the core of an object.
#[derive(Clone, Debug)]
pub(crate) struct Dnode {
    pub kind: u8,
    pub indblkshift: u8,
    pub nlevels: u8,
    pub bonustype: u8,
    pub datablksz: u64,
    pub maxblkid: u64,
    pub used: u64,
    pub bps: Vec<Bp>,
    pub bonus: Vec<u8>,
    pub spill: Option<Bp>,
    pub le: bool,
}

pub(crate) const DNODE_SIZE: usize = 512;
const FLAG_USED_BYTES: u8 = 1;
const FLAG_SPILL: u8 = 4;

impl Dnode {
    /// Parses a dnode of `b.len()` bytes (one or more 512-byte slots) in byte order `le`.
    pub fn parse(b: &[u8], le: bool) -> Result<Dnode> {
        let bad = |what: &str| Error::corrupt(format!("dnode: {what}"));
        if b.len() < DNODE_SIZE {
            return Err(bad("shorter than 512 bytes"));
        }
        let kind = b[0];
        let (indblkshift, nlevels, nblkptr, bonustype, flags) = (b[1], b[2], b[3], b[4], b[7]);
        if kind == 0 {
            return Err(bad("object is free"));
        }
        let datablksz = u64::from(u16e(b, 8, le)) << 9;
        let bonuslen = usize::from(u16e(b, 10, le));
        if !(1..=3).contains(&nblkptr) || !(1..=MAX_LEVELS).contains(&nlevels) {
            return Err(bad("block pointer count or levels out of range"));
        }
        if !(10..=17).contains(&indblkshift) && nlevels > 1 {
            return Err(bad("indirect block size out of range"));
        }
        if datablksz == 0 || datablksz > MAX_BLOCK {
            return Err(bad("data block size out of range"));
        }
        let bonus_at = 64 + 128 * usize::from(nblkptr);
        let spill = flags & FLAG_SPILL != 0;
        let room = b.len().saturating_sub(bonus_at + if spill { 128 } else { 0 });
        if bonuslen > room {
            return Err(bad("bonus buffer larger than the dnode"));
        }
        let bps = (0..usize::from(nblkptr)).map(|i| Bp::parse(b, 64 + 128 * i, le)).collect();
        let used = u64e(b, 24, le);
        Ok(Dnode {
            kind,
            indblkshift,
            nlevels,
            bonustype,
            datablksz,
            maxblkid: u64e(b, 16, le),
            used: if flags & FLAG_USED_BYTES != 0 { used } else { used.saturating_mul(512) },
            bps,
            bonus: b[bonus_at..bonus_at + bonuslen].to_vec(),
            spill: spill.then(|| Bp::parse(b, b.len() - 128, le)),
            le,
        })
    }

    /// The block pointer of level-0 block `blkid`, through the indirect blocks; `None` for
    /// a hole or a block past the end.
    pub fn block_bp<R: ReadAt>(&self, pool: &Pool<R>, cache: &mut Cache, blkid: u64) -> Result<Option<Bp>> {
        if blkid > self.maxblkid {
            return Ok(None);
        }
        let epbs = u32::from(self.indblkshift).saturating_sub(7);
        let levels = u32::from(self.nlevels);
        let shift = epbs * (levels - 1);
        let top = if shift >= 64 { 0 } else { blkid >> shift };
        let Some(&first) = usize::try_from(top).ok().and_then(|t| self.bps.get(t)) else { return Ok(None) };
        let mut bp = first;
        for level in (1..levels).rev() {
            if bp.hole() {
                return Ok(None);
            }
            if u32::from(bp.level()) != level {
                return Err(Error::corrupt(format!("indirect block at level {} where {level} belongs", bp.level())));
            }
            let block = pool.read(cache, &bp)?;
            let shift = epbs * (level - 1);
            let index = if shift >= 64 { 0 } else { (blkid >> shift) & ((1 << epbs) - 1) } as usize;
            if (index + 1) * 128 > block.data.len() {
                return Err(Error::corrupt("indirect block shorter than its index"));
            }
            bp = Bp::parse(&block.data, index * 128, block.le);
        }
        if bp.hole() {
            return Ok(None);
        }
        if bp.level() != 0 {
            return Err(Error::corrupt(format!("data block at level {}", bp.level())));
        }
        Ok(Some(bp))
    }

    /// Level-0 block `blkid`, `None` for a hole.
    pub fn block<R: ReadAt>(&self, pool: &Pool<R>, cache: &mut Cache, blkid: u64) -> Result<Option<Arc<Block>>> {
        match self.block_bp(pool, cache, blkid)? {
            Some(bp) => pool.read(cache, &bp).map(Some),
            None => Ok(None),
        }
    }

    /// Fills `buf` from byte `offset` of the object's data; holes and the space past the last
    /// block read as zeros.
    pub fn read<R: ReadAt>(&self, pool: &Pool<R>, cache: &mut Cache, offset: u64, buf: &mut [u8]) -> Result<()> {
        buf.fill(0);
        let bs = self.datablksz;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let (blkid, within) = (at / bs, (at % bs) as usize);
            let n = (bs as usize - within).min(buf.len() - done);
            if let Some(block) = self.block(pool, cache, blkid)? {
                let src = block.data.get(within..).unwrap_or(&[]);
                let m = src.len().min(n);
                buf[done..done + m].copy_from_slice(&src[..m]);
            }
            done += n;
            if blkid >= self.maxblkid {
                break;
            }
        }
        Ok(())
    }
}

/// Building blocks for tests: a one-device pool in memory and block pointers into it.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A pool whose single disk holds `blocks` at their offsets (past the 4 MiB label area).
    pub fn pool(blocks: &[(u64, Vec<u8>)]) -> Pool<crate::Bytes<'static>> {
        let end = blocks.iter().map(|(at, b)| at + b.len() as u64).max().unwrap_or(0);
        let mut disk = vec![0u8; (LABEL_START + end + 4096) as usize];
        for (at, b) in blocks {
            let at = (LABEL_START + at) as usize;
            disk[at..at + b.len()].copy_from_slice(b);
        }
        let disk: &'static [u8] = Box::leak(disk.into_boxed_slice());
        let top = vec![Some(Vdev::Leaf { guid: 1, dev: Some(0) })];
        Pool { devices: vec![crate::Bytes(disk)], top, decompress: None, shared: Default::default() }
    }

    /// An uncompressed block pointer to `size` bytes at `offset`, in byte order `le` (for its
    /// own fields and the block's), with the block's type and level.
    pub fn bp(offset: u64, size: u64, kind: u64, level: u64, le: bool) -> Vec<u8> {
        let sectors = size / 512 - 1;
        let prop = sectors | sectors << 16 | COMPRESS_OFF << 32 | kind << 48 | level << 56 | u64::from(le) << 63;
        let mut words = [0u64; 16];
        (words[0], words[1], words[6], words[10]) = (size / 512, offset / 512, prop, 1);
        words.iter().flat_map(|w| if le { w.to_le_bytes() } else { w.to_be_bytes() }).collect()
    }

    /// A dnode of one 512-byte slot with these block pointers, in byte order `le`.
    pub fn dnode(kind: u8, nlevels: u8, datablksz: u64, maxblkid: u64, bps: &[Vec<u8>], le: bool) -> Dnode {
        let mut b = vec![0u8; DNODE_SIZE];
        (b[0], b[1], b[2], b[3]) = (kind, 12, nlevels, bps.len() as u8);
        let put16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        b[8..10].copy_from_slice(&put16((datablksz / 512) as u16));
        b[16..24].copy_from_slice(&if le { maxblkid.to_le_bytes() } else { maxblkid.to_be_bytes() });
        for (i, bp) in bps.iter().enumerate() {
            b[64 + 128 * i..192 + 128 * i].copy_from_slice(bp);
        }
        Dnode::parse(&b, le).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn an_indirect_block_pointing_at_itself_is_refused_by_its_level() {
        // A three-level object whose level-2 block's first pointer is itself.
        let indirect = bp(0, 4096, 20, 2, true);
        let mut block = vec![0u8; 4096];
        block[..128].copy_from_slice(&indirect);
        let pool = pool(&[(0, block)]);
        let dn = dnode(20, 3, 512, 100, &[indirect], true);
        let mut cache = Cache::new();
        let err = dn.block(&pool, &mut cache, 0).err().unwrap();
        assert!(err.to_string().contains("level 2 where 1 belongs"), "{err}");
        // An address past the end of the device, and a block bigger than 16 MiB.
        let far = bp(1 << 40, 512, 19, 0, true);
        let dn = dnode(19, 1, 512, 0, &[far], true);
        assert!(dn.block(&pool, &mut cache, 0).is_err());
        let mut huge = bp(0, 512, 19, 0, true);
        huge[48..50].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(pool.read(&mut cache, &Bp::parse(&huge, 0, true)).is_err());
    }

    #[test]
    fn big_endian_blocks_and_dnodes() {
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        let pool = pool(&[(8192, data)]);
        let dn = dnode(19, 1, 512, 0, &[bp(8192, 512, 19, 0, false)], false);
        assert_eq!((dn.datablksz, dn.maxblkid, dn.le), (512, 0, false));
        let block = dn.block(&pool, &mut Cache::new(), 0).unwrap().unwrap();
        assert!(!block.le);
        assert_eq!(u64e(&block.data, 0, block.le), 0x0102_0304_0506_0708);
    }

    fn bp_with(prop: u64, dva: (u64, u64)) -> Bp {
        let mut words = [0u64; 16];
        (words[0], words[1], words[6]) = (dva.0, dva.1, prop);
        Bp { words }
    }

    #[test]
    fn block_pointer_fields() {
        // lsize 128 KiB (255), psize 4 KiB (7), lz4, type 19, level 0, little-endian.
        let prop = 255 | 7 << 16 | 15 << 32 | 19 << 48 | 1 << 63;
        let bp = bp_with(prop, (1 << 32 | 8, 0x1000));
        assert_eq!((bp.lsize(), bp.psize(), bp.compression(), bp.kind(), bp.level()), (128 << 10, 4096, 15, 19, 0));
        assert!(bp.little_endian() && !bp.hole() && !bp.embedded());
        assert_eq!(bp.dva(0), Some(Dva { vdev: 1, offset: 0x1000 * 512, asize: 4096, gang: false }));
        assert_eq!(bp.dva(1), None);
        assert!(bp_with(prop, (0, 0)).hole());
        assert_eq!(bp_with(prop, (1, u64::MAX >> 1)).dva(0), None);
        assert!(bp_with(prop, (1, 1 << 63)).dva(0).unwrap().gang);
    }

    #[test]
    fn embedded_payload_skips_two_words() {
        let mut words = [0u64; 16];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u64::from_le_bytes([i as u8; 8]);
        }
        // lsize 100 (99), psize 20 (19), compression off, embedded.
        words[6] = 99 | 19 << 25 | 2 << 32 | 1 << 39;
        let bp = Bp { words };
        assert_eq!((bp.lsize(), bp.psize()), (100, 20));
        assert_eq!(bp.payload(), [[0u8; 8], [1; 8], [2; 8]].concat()[..20]);
        words[6] = 99 | 127 << 25 | 1 << 39;
        let full = Bp { words }.payload();
        assert_eq!(full.len(), 112);
        assert_eq!(&full[48..56], &[7; 8]);
        assert_eq!(&full[72..80], &[11; 8]);
    }

    #[test]
    fn raidz_layout() {
        // RAID-Z1 over 3 children, 4 KiB sectors, 128 KiB at offset 0: 16 rows on each data
        // column, data on children 1 and 2.
        let cols = raidz_columns(0, 128 << 10, 1, 12, 3).unwrap();
        assert_eq!(cols, [(1, 0, 64 << 10), (2, 0, 64 << 10)]);
        // One sector at sector 4: on child 4 % 3 + 1 = 2 at row 1.
        assert_eq!(raidz_columns(4 << 12, 4096, 1, 12, 3).unwrap(), [(2, 4096, 4096)]);
        // Three sectors at sector 2: parity on child 2, data wraps to the next row.
        assert_eq!(raidz_columns(2 << 12, 3 << 12, 1, 12, 3).unwrap(), [(0, 4096, 8192), (1, 4096, 4096)]);
        // In the second MiB, single parity swaps with the first data column.
        assert_eq!(raidz_columns(3 << 20, 8192, 1, 12, 3).unwrap(), [(0, 1 << 20, 4096), (2, 1 << 20, 4096)]);
        assert!(raidz_columns(0, 4096, 0, 12, 3).is_err());
        assert!(raidz_columns(0, 4096, 2, 12, 2).is_err());
    }
}

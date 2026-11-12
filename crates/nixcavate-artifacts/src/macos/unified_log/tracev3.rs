//! The tracev3 container: chunks, the header chunk, catalog chunks and LZ4 chunk sets.
//! Format: libyal dtformats, "Apple Unified Logging and Activity Tracing formats", sections
//! "tracev3 chunk", "Header (chunk)", "Catalog chunk" and "LZ4 compressed data".

use std::collections::HashMap;

pub const HEADER: u32 = 0x1000;
pub const FIREHOSE: u32 = 0x6001;
pub const OVERSIZE: u32 = 0x6002;
pub const STATEDUMP: u32 = 0x6003;
pub const SIMPLEDUMP: u32 = 0x6004;
pub const CATALOG: u32 = 0x600b;
pub const CHUNKSET: u32 = 0x600d;

/// The largest chunk set block we decompress. Real blocks are well under 1 MiB.
const MAX_BLOCK: usize = 16 << 20;

pub type Uuid = [u8; 16];

/// Bounds-checked little-endian reads; every read returns `None` past the end.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(out)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N)?.try_into().ok()
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    pub fn uuid(&mut self) -> Option<Uuid> {
        self.array()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    pub fn align8(&mut self) {
        self.pos = self.pos.saturating_add(7) & !7;
    }
}

/// A little-endian unsigned integer of up to 8 bytes (extra bytes are ignored).
pub fn le(bytes: &[u8]) -> u64 {
    bytes.iter().take(8).rev().fold(0, |v, &b| v << 8 | b as u64)
}

/// A NUL-terminated string at the start of `bytes` (all of it when there is no NUL).
pub fn cstr(bytes: &[u8]) -> &[u8] {
    &bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())]
}

pub fn uuid_string(uuid: &Uuid) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
        s.push(char::from(b"0123456789ABCDEF"[(b & 15) as usize]));
    }
    s
}

fn known(tag: u32) -> bool {
    matches!(tag, HEADER | FIREHOSE | OVERSIZE | STATEDUMP | SIMPLEDUMP | CATALOG | CHUNKSET)
}

pub struct Chunk<'a> {
    pub tag: u32,
    /// Offset of the chunk preamble within the buffer it was read from.
    pub offset: usize,
    pub data: &'a [u8],
}

/// Walks the 8-byte aligned chunks of a buffer. A chunk whose declared size runs past the end
/// is returned as an error and ends the walk; every step advances by at least 16 bytes.
pub struct Chunks<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Chunks<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Result<Chunk<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut r = Reader { data: self.data, pos: self.pos };
        let tag = r.u32()?;
        let offset = self.pos;
        let (_subtag, len) = (r.u32()?, r.u64()?);
        let Some(data) = usize::try_from(len).ok().and_then(|len| r.bytes(len)) else {
            self.pos = self.data.len();
            let unread = self.data.len() - offset;
            return Some(Err(format!(
                "chunk 0x{tag:x} at {offset} declares {len} bytes past the end; {unread} bytes left unread"
            )));
        };
        // Each chunk is padded to a multiple of 8 bytes, except a few that are followed
        // directly by the next chunk; those are recognized by the tag that follows.
        let end = r.pos;
        let padded = offset + (end - offset).next_multiple_of(8);
        let tag_at = |at: usize| Reader { data: self.data, pos: at }.u32().filter(|&t| known(t));
        self.pos = if tag_at(padded).is_none() && tag_at(end).is_some() { end } else { padded };
        Some(Ok(Chunk { tag, offset, data }))
    }
}

/// The header chunk: the timebase, the wall clock at file creation and the boot.
pub struct Header {
    pub numerator: u32,
    pub denominator: u32,
    pub continuous: u64,
    pub wall_secs: i64,
    pub boot: Uuid,
}

impl Header {
    pub fn parse(data: &[u8]) -> Option<Header> {
        let mut r = Reader::new(data);
        let (numerator, denominator, start) = (r.u32()?, r.u32()?, r.u64()?);
        let wall_secs = r.u32()? as i64;
        r.pos = 40; // two unknowns, zone offset, DST flag and header flags
        let mut header = Header { numerator, denominator, continuous: start, wall_secs, boot: [0; 16] };
        // Sub chunks: continuous time (0x6100), system info (0x6101), generation (0x6102)...
        while let (Some(tag), Some(size)) = (r.u32(), r.u32()) {
            let Some(mut body) = r.bytes(size as usize).map(Reader::new) else { break };
            match tag {
                0x6100 => header.continuous = body.u64().unwrap_or(start),
                0x6102 => header.boot = body.uuid().unwrap_or_default(),
                _ => {}
            }
        }
        Some(header)
    }
}

/// An image loaded into a process, from a catalog "UUID information entry".
pub struct Image {
    pub uuid: Uuid,
    pub load_address: u64,
    pub size: u32,
}

pub struct Process {
    pub pid: u32,
    pub euid: u32,
    pub main: Option<Uuid>,
    pub dsc: Option<Uuid>,
    pub images: Vec<Image>,
    /// Subsystem identifier to (subsystem, category) string offsets.
    pub subsystems: Vec<(u16, u16, u16)>,
}

/// A catalog chunk: the processes whose entries follow in the next chunk sets.
pub struct Catalog<'a> {
    strings: &'a [u8],
    /// By first and second proc_id.
    processes: HashMap<(u64, u32), Process>,
}

impl<'a> Catalog<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Catalog<'a>> {
        let mut r = Reader::new(data);
        let (strings_at, procs_at, proc_count, chunks_at) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        let base = 24; // offsets are relative to the UUID array
        let uuid_bytes = data.get(base..base + strings_at as usize)?;
        let uuids: Vec<Uuid> = uuid_bytes.chunks_exact(16).filter_map(|u| u.try_into().ok()).collect();
        let strings = data.get(base + strings_at as usize..base + procs_at as usize)?;
        let uuid_at = |index: u16| uuids.get(index as usize).copied();

        let mut r = Reader { data: data.get(..base + chunks_at as usize)?, pos: base + procs_at as usize };
        let mut processes = HashMap::with_capacity(proc_count as usize);
        for _ in 0..proc_count {
            let (_index, _unknown, main, dsc) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
            let (first, second, pid, euid) = (r.u64()?, r.u32()?, r.u32()?, r.u32()?);
            let (_unknown, image_count, _unknown2) = (r.u32()?, r.u32()?, r.u32()?);
            let mut images = Vec::with_capacity((image_count as usize).min(r.rest().len() / 16));
            for _ in 0..image_count {
                let (size, _unknown, index) = (r.u32()?, r.u32()?, r.u16()?);
                let load_address = r.u32()? as u64 | (r.u16()? as u64) << 32;
                if let Some(uuid) = uuid_at(index) {
                    images.push(Image { uuid, load_address, size });
                }
            }
            let (subsystem_count, _unknown) = (r.u32()?, r.u32()?);
            let mut subsystems = Vec::with_capacity((subsystem_count as usize).min(r.rest().len() / 6));
            for _ in 0..subsystem_count {
                subsystems.push((r.u16()?, r.u16()?, r.u16()?));
            }
            r.align8();
            let process = Process { pid, euid, main: uuid_at(main), dsc: uuid_at(dsc), images, subsystems };
            processes.insert((first, second), process);
        }
        Some(Catalog { strings, processes })
    }

    pub fn process(&self, first: u64, second: u32) -> Option<&Process> {
        self.processes.get(&(first, second))
    }

    pub fn string(&self, offset: u16) -> &'a [u8] {
        cstr(self.strings.get(offset as usize..).unwrap_or_default())
    }

    /// The subsystem and category names for a subsystem identifier.
    pub fn subsystem(&self, process: &Process, id: u16) -> Option<(&'a [u8], &'a [u8])> {
        let &(_, subsystem, category) = process.subsystems.iter().find(|s| s.0 == id)?;
        Some((self.string(subsystem), self.string(category)))
    }
}

/// Decompresses a chunk set into `out` and returns the length used. The blocks are
/// `bv41` (LZ4 block), `bv4-` (stored) and the `bv4$` end marker.
pub fn decompress(data: &[u8], out: &mut Vec<u8>) -> Result<usize, String> {
    let mut r = Reader::new(data);
    let mut len = 0usize;
    while let Some(marker) = r.bytes(4) {
        let size = match marker {
            b"bv4$" => break,
            b"bv41" | b"bv4-" => r.u32().ok_or("truncated block header")? as usize,
            other => return Err(format!("unknown block marker {:?}", String::from_utf8_lossy(other))),
        };
        let end = len.checked_add(size).filter(|&end| end <= MAX_BLOCK).ok_or("block too large")?;
        if out.len() < end {
            out.resize(end, 0);
        }
        if marker == b"bv41" {
            let compressed = r.u32().and_then(|n| r.bytes(n as usize)).ok_or("truncated LZ4 block")?;
            let n = lz4_flex::block::decompress_into(compressed, &mut out[len..end]).map_err(|e| e.to_string())?;
            if n != size {
                return Err(format!("LZ4 block gave {n} bytes, expected {size}"));
            }
        } else {
            out[len..end].copy_from_slice(r.bytes(size).ok_or("truncated stored block")?);
        }
        len = end;
    }
    Ok(len)
}

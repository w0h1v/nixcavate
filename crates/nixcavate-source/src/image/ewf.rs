//! Expert Witness Compression Format (EWF-E01, EnCase 1 to 7 style) reader.
//!
//! Written from the libyal specification "Expert Witness Compression Format (EWF)"
//! (libewf `documentation/Expert Witness Compression Format (EWF).asciidoc`) and checked
//! against files made by `ewfacquire`. The parts used here:
//!
//! * Segment files `.E01`, `.E02`, ... start with a 13-byte file header: the signature
//!   `EVF\x09\x0d\x0a\xff\x00`, a start-of-fields byte (1), the segment number (u16) and an
//!   end-of-fields u16 (0). Everything after it is a chain of sections.
//! * A section starts with a 76-byte descriptor: a 16-byte zero-padded type string, the
//!   absolute file offset of the next descriptor (u64), the section size including the
//!   descriptor (u64), 40 bytes of padding and the Adler-32 (u32) of the first 72 bytes.
//!   The chain ends at a `done` section (last segment) or `next` section (more segments follow);
//!   both point at themselves.
//! * `volume` / `disk` (first segment): chunk count (u32 at +4), sectors per chunk (u32 at
//!   +8), bytes per sector (u32 at +12), sector count (u64 at +16).
//! * `sectors` holds the chunks, followed by `table` (and a `table2` mirror). A table has a
//!   24-byte header (entry count u32, 4 bytes padding, base offset u64, 4 bytes padding,
//!   Adler-32 of the first 20 bytes) and then one u32 per chunk. Bit 31 marks a zlib-compressed
//!   chunk; the low 31 bits plus the base offset are the chunk's offset in the segment file.
//!   A chunk ends where the next one starts; the last one ends where the `sectors` section ends.
//!   A chunk that is not compressed is the raw bytes followed by their Adler-32 (little endian).
//!
//! A table's chunks must lie after every chunk an earlier table of the segment listed, so each
//! byte of chunk data belongs to one chunk: tables that point at the same data (which would
//! let a small file present a huge disk) are refused.
//!
//! EWF version 2 (`Ex01`, signature `EVF2`) and logical evidence (`L01`) are detected and
//! refused with a clear error.
//!
//! Every count and offset is bounds-checked against the mapped segment before use. The only
//! allocations sized by a field of the file are a chunk (at most [`MAX_CHUNK`]) and the chunk
//! list (one entry per table entry present in the file); decoded chunks kept for reuse take at
//! most [`CACHE_BYTES`].

use crate::map;
use nixcavate_fs::{adler32, le32, le64, ReadAt};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SIGNATURE: [u8; 8] = *b"EVF\x09\x0d\x0a\xff\x00";
const SIGNATURE_V2: [u8; 8] = *b"EVF2\x0d\x0a\x81\x00";
const SIGNATURE_LOGICAL: [u8; 8] = *b"LVF\x09\x0d\x0a\xff\x00";

const FILE_HEADER_LEN: usize = 13;
const DESCRIPTOR_LEN: usize = 76;
const TABLE_HEADER_LEN: usize = 24;
/// Largest chunk accepted. The usual chunk is 64 sectors of 512 bytes (32 KiB, EnCase's and
/// ewfacquire's default); ewfacquire offers up to 32768 sectors per chunk, 16 MiB with 512-byte
/// sectors. Larger chunks come only from forged geometry.
const MAX_CHUNK: u64 = 16 << 20;
/// Decompressed chunks kept for reuse: at most 16, and at most this many bytes.
const CACHE_CHUNKS: usize = 16;
const CACHE_BYTES: u64 = 64 << 20;
/// Segment extensions run `E01`..`E99`, `EAA`..`ZZZ`; this bounds the probe loop.
const MAX_SEGMENTS: u32 = 99 + 26 * 26 * 21;

/// What kind of EWF-family file `head` starts like, if any.
pub enum Signature {
    /// EWF version 1 (E01): readable.
    V1,
    /// A recognised but unsupported EWF variant; the string names it.
    Unsupported(&'static str),
}

pub fn signature(head: &[u8]) -> Option<Signature> {
    match head.get(..8)? {
        s if s == SIGNATURE => Some(Signature::V1),
        s if s == SIGNATURE_V2 => Some(Signature::Unsupported("EWF version 2 (Ex01) images are not supported")),
        s if s == SIGNATURE_LOGICAL => Some(Signature::Unsupported("EWF logical evidence (L01) is not supported")),
        _ => None,
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("EWF: {}", msg.into()))
}

/// Where one chunk lives.
#[derive(Clone, Copy)]
struct Chunk {
    /// Offset in its segment file.
    offset: u64,
    /// Bytes on disk, up to the next chunk (compressed size, or raw size plus checksum).
    len: u32,
    segment: u16,
    compressed: bool,
}

struct Geometry {
    chunk_size: u64,
    size: u64,
}

struct Slot {
    index: u64,
    used: u64,
    data: Arc<Vec<u8>>,
}

#[derive(Default)]
struct Cache {
    tick: u64,
    slots: Vec<Slot>,
}

pub type Segment = Box<dyn AsRef<[u8]> + Send + Sync>;

/// A whole EWF image: all segment files, presented as the acquired disk.
pub struct Ewf {
    segments: Vec<Segment>,
    chunks: Vec<Chunk>,
    chunk_size: u64,
    size: u64,
    /// A mutex rather than a per-thread cache: tasks read in parallel, and the lock is held
    /// only to look up or insert, never while a chunk is being decompressed.
    cache: Mutex<Cache>,
}

impl Ewf {
    /// Opens the image whose first segment is `first`, finding `.E02`, `.E03`, ... beside it.
    pub fn open(first: &Path) -> io::Result<Ewf> {
        let mut paths = vec![first.to_path_buf()];
        for n in 2..=MAX_SEGMENTS {
            match segment_path(first, n) {
                Some(path) if path.is_file() => paths.push(path),
                _ => break,
            }
        }
        let mut segments: Vec<Segment> = Vec::with_capacity(paths.len());
        for path in &paths {
            if std::fs::metadata(path)?.len() < FILE_HEADER_LEN as u64 {
                return Err(bad(format!("{} is too short", path.display())));
            }
            segments.push(Box::new(map(path)?));
        }
        Ewf::from_segments(segments)
    }

    /// Builds an image from segment files already in memory, in segment order.
    pub fn from_segments(segments: Vec<Segment>) -> io::Result<Ewf> {
        if segments.len() > u16::MAX as usize {
            return Err(bad("too many segment files"));
        }
        let mut geometry: Option<Geometry> = None;
        let mut chunks: Vec<Chunk> = Vec::new();
        for (index, segment) in segments.iter().enumerate() {
            let data: &[u8] = (**segment).as_ref();
            let last = index + 1 == segments.len();
            read_segment(data, index, last, &mut geometry, &mut chunks)?;
        }
        let Geometry { chunk_size, size } = geometry.ok_or_else(|| bad("no volume section"))?;
        let needed = size.div_ceil(chunk_size);
        if (chunks.len() as u64) < needed {
            return Err(bad(format!(
                "the segments hold {} of {needed} chunks (is a segment file missing?)",
                chunks.len()
            )));
        }
        chunks.truncate(needed as usize);
        Ok(Ewf { segments, chunks, chunk_size, size, cache: Mutex::new(Cache::default()) })
    }

    fn chunk(&self, index: u64) -> io::Result<Arc<Vec<u8>>> {
        let lock = || self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let mut cache = lock();
            cache.tick += 1;
            let tick = cache.tick;
            if let Some(slot) = cache.slots.iter_mut().find(|s| s.index == index) {
                slot.used = tick;
                return Ok(slot.data.clone());
            }
        }
        let data = Arc::new(self.decode(index)?);
        let mut cache = lock();
        cache.tick += 1;
        let slot = Slot { index, used: cache.tick, data: data.clone() };
        let room = (CACHE_BYTES / self.chunk_size).clamp(1, CACHE_CHUNKS as u64) as usize;
        if cache.slots.len() < room {
            cache.slots.push(slot);
        } else if let Some(oldest) = cache.slots.iter_mut().min_by_key(|s| s.used) {
            *oldest = slot;
        }
        Ok(data)
    }

    fn decode(&self, index: u64) -> io::Result<Vec<u8>> {
        let chunk = self.chunks.get(index as usize).ok_or_else(|| bad("chunk index out of range"))?;
        let segment: &[u8] = (**self.segments.get(chunk.segment as usize).ok_or_else(|| bad("bad segment"))?).as_ref();
        let start = usize::try_from(chunk.offset).map_err(|_| bad("chunk offset"))?;
        let raw = segment
            .get(start..start.checked_add(chunk.len as usize).ok_or_else(|| bad("chunk offset"))?)
            .ok_or_else(|| bad(format!("chunk {index} lies outside its segment file")))?;
        // The last chunk may be short.
        let expected = self.chunk_size.min(self.size - index * self.chunk_size) as usize;
        if chunk.compressed {
            let mut out = Vec::with_capacity(expected);
            // Reading one byte past the expected size makes the decoder reach the end of the
            // stream, which is where it verifies the zlib checksum.
            flate2::read::ZlibDecoder::new(raw)
                .take(expected as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| bad(format!("chunk {index}: {e}")))?;
            if out.len() != expected {
                return Err(bad(format!("chunk {index} decompressed to {} bytes, expected {expected}", out.len())));
            }
            Ok(out)
        } else {
            let body = raw.get(..expected).ok_or_else(|| bad(format!("chunk {index} is shorter than its size")))?;
            if raw.len() < expected + 4 {
                return Err(bad(format!("chunk {index} has no checksum")));
            }
            if adler32(body) != le32(raw, expected) {
                return Err(bad(format!("chunk {index} fails its checksum")));
            }
            Ok(body.to_vec())
        }
    }
}

impl ReadAt for Ewf {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        match offset.checked_add(buf.len() as u64) {
            Some(end) if end <= self.size => {}
            _ => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the image")),
        }
        let mut done = 0;
        while done < buf.len() {
            let position = offset + done as u64;
            let chunk = self.chunk(position / self.chunk_size)?;
            let within = (position % self.chunk_size) as usize;
            let part = chunk.get(within..).ok_or_else(|| bad("short chunk"))?;
            let n = part.len().min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&part[..n]);
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// The path of segment `number` (1 is `first` itself): `.E01`..`.E99`, then `.EAA`..`.EZZ`,
/// `.FAA`.. The case of the first extension is kept. `None` if `first` does not look like one.
fn segment_path(first: &Path, number: u32) -> Option<PathBuf> {
    let ext = first.extension()?.to_str()?;
    let bytes = ext.as_bytes();
    if bytes.len() != 3 || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let lower = bytes[0].is_ascii_lowercase();
    let base = bytes[0].to_ascii_uppercase();
    let name = if number <= 99 {
        format!("{}{number:02}", base as char)
    } else {
        let index = number - 100;
        let letter = base.checked_add((index / 676) as u8).filter(|l| *l <= b'Z')?;
        let (b, c) = ((index % 676) / 26, index % 26);
        format!("{}{}{}", letter as char, (b'A' + b as u8) as char, (b'A' + c as u8) as char)
    };
    let name = if lower { name.to_ascii_lowercase() } else { name };
    Some(first.with_extension(name))
}

/// Walks the section chain of one segment file, collecting geometry and chunk locations.
fn read_segment(
    data: &[u8],
    index: usize,
    last: bool,
    geometry: &mut Option<Geometry>,
    chunks: &mut Vec<Chunk>,
) -> io::Result<()> {
    let head = data.get(..FILE_HEADER_LEN).ok_or_else(|| bad(format!("segment {} is too short", index + 1)))?;
    match signature(head) {
        Some(Signature::V1) => {}
        Some(Signature::Unsupported(why)) => return Err(io::Error::new(io::ErrorKind::Unsupported, why)),
        None => return Err(bad(format!("segment {} has no EWF signature", index + 1))),
    }
    let number = u16::from_le_bytes([head[9], head[10]]) as usize;
    if number != index + 1 {
        return Err(bad(format!("segment file {} says it is number {number}", index + 1)));
    }

    let mut at = FILE_HEADER_LEN;
    // The most recent `sectors` section's data: where its chunks may start and where its last
    // chunk stops.
    let mut sectors: Option<(u64, u64)> = None;
    // Where the chunks listed so far end: a later table's chunks must start at or after it.
    let mut floor = 0u64;
    // A `table2` is read only to replace a `table` that failed its checksum.
    let mut table_failed = false;
    // Each section starts after the previous one, so the loop ends within `data.len()/76` steps.
    loop {
        let desc = data
            .get(at..at.saturating_add(DESCRIPTOR_LEN))
            .ok_or_else(|| bad(format!("segment {}: section descriptor at {at} is cut off", index + 1)))?;
        if adler32(&desc[..72]) != le32(desc, 72) {
            return Err(bad(format!("segment {}: section descriptor at {at} fails its checksum", index + 1)));
        }
        let kind = &desc[..16];
        let kind = &kind[..kind.iter().position(|&b| b == 0).unwrap_or(16)];
        let next = le64(desc, 16);
        let size = le64(desc, 24);
        let body_start = at + DESCRIPTOR_LEN;
        let section_end = (at as u64).checked_add(size).filter(|&e| e <= data.len() as u64 && size >= 76);
        let body = section_end.and_then(|end| data.get(body_start..end as usize));

        match kind {
            b"volume" | b"disk" if geometry.is_none() => {
                *geometry = Some(parse_volume(body.ok_or_else(|| bad("volume section is cut off"))?)?);
            }
            b"sectors" => sectors = section_end.map(|end| (body_start as u64, end)),
            b"table" | b"table2" if kind == b"table" || table_failed => {
                let geometry = geometry.as_ref().ok_or_else(|| bad("table before the volume section"))?;
                // Without a `sectors` section (early EnCase), the chunks run up to the table.
                let (start, run_end) = sectors.unwrap_or((0, at as u64));
                let run = (start.max(floor), run_end);
                let result = body
                    .ok_or_else(|| bad("table section is cut off"))
                    .and_then(|body| parse_table(body, run, data.len() as u64, index, geometry, chunks));
                match result {
                    Ok(end) => {
                        table_failed = false;
                        floor = floor.max(end);
                    }
                    Err(_) if kind == b"table" && table2_follows(data, next, at) => table_failed = true,
                    Err(e) => return Err(e),
                }
            }
            _ => {}
        }

        match kind {
            b"done" => {
                return if last {
                    Ok(())
                } else {
                    Err(bad(format!("segment {} ends the image but more segment files follow", index + 1)))
                };
            }
            b"next" => {
                return if last { Err(bad("the image continues in a segment file that is missing")) } else { Ok(()) };
            }
            _ => {}
        }
        if next <= at as u64 {
            return Err(bad(format!("segment {}: section at {at} does not advance", index + 1)));
        }
        at = usize::try_from(next).map_err(|_| bad("section offset"))?;
    }
}

/// Whether the section that follows the one at `at` (whose `next` field is given) is a
/// `table2`, the mirror that can stand in for a table that failed its checksum.
fn table2_follows(data: &[u8], next: u64, at: usize) -> bool {
    let Ok(next) = usize::try_from(next) else { return false };
    next > at && next.checked_add(16).and_then(|end| data.get(next..end)).is_some_and(|k| k.starts_with(b"table2\0"))
}

fn parse_volume(body: &[u8]) -> io::Result<Geometry> {
    if body.len() < 24 {
        return Err(bad("volume section is too short"));
    }
    let spc = u64::from(le32(body, 8));
    let bps = u64::from(le32(body, 12));
    let sectors = le64(body, 16);
    let chunk_size = spc * bps; // both fit in 32 bits
    if spc == 0 || bps == 0 || chunk_size > MAX_CHUNK {
        return Err(bad(format!("implausible chunk geometry ({spc} sectors of {bps} bytes)")));
    }
    let size = sectors.checked_mul(bps).filter(|&s| s > 0).ok_or_else(|| bad("implausible sector count"))?;
    Ok(Geometry { chunk_size, size })
}

/// Appends the chunks of one `table` (or `table2`) section, which must lie in `run` (the
/// byte range of the segment that holds this table's chunk data). Returns where they end.
fn parse_table(
    body: &[u8],
    run: (u64, u64),
    segment_len: u64,
    segment: usize,
    geometry: &Geometry,
    chunks: &mut Vec<Chunk>,
) -> io::Result<u64> {
    let (run_start, run_end) = run;
    let header = body.get(..TABLE_HEADER_LEN).ok_or_else(|| bad("table section is too short"))?;
    if adler32(&header[..20]) != le32(header, 20) {
        return Err(bad("table header fails its checksum"));
    }
    let count = le32(header, 0) as usize;
    let base = le64(header, 8);
    let entries = TABLE_HEADER_LEN
        .checked_add(count.checked_mul(4).ok_or_else(|| bad("table size"))?)
        .and_then(|end| body.get(TABLE_HEADER_LEN..end))
        .ok_or_else(|| bad("table entries run past the section"))?;
    // The image needs only so many chunks; ignore entries past that.
    let room = geometry.size.div_ceil(geometry.chunk_size).saturating_sub(chunks.len() as u64) as usize;
    let used = count.min(room);
    let mut starts = Vec::with_capacity(used);
    let mut found = Vec::with_capacity(used);
    for entry in entries.chunks_exact(4).take(used) {
        let value = u32::from_le_bytes(entry.try_into().unwrap_or([0; 4]));
        let offset = base.checked_add((value & 0x7fff_ffff) as u64).ok_or_else(|| bad("chunk offset"))?;
        starts.push((offset, value >> 31 == 1));
    }
    // The last chunk ends where its sectors section ends, if that is a sane place. Chunks
    // follow each other, so a chunk that starts before the previous one ends has no extent.
    let tail = run_end.min(segment_len);
    if starts.first().is_some_and(|&(offset, _)| offset < run_start) {
        return Err(bad("a table's chunks overlap chunks listed before them"));
    }
    for (i, &(offset, compressed)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(tail, |next| next.0);
        let len = end.checked_sub(offset).filter(|&l| l > 0 && end <= segment_len && l <= u32::MAX as u64);
        let len = len.ok_or_else(|| bad(format!("chunk at offset {offset} has no valid extent")))?;
        found.push(Chunk { offset, len: len as u32, segment: segment as u16, compressed });
    }
    // Only a table that parsed completely contributes, so a failed one can be replaced by table2.
    chunks.extend(found);
    Ok(tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    pub(crate) fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image")
    }

    /// Size of the acquired image: not a multiple of the chunk size, so the last chunk is short.
    pub(crate) const IMAGE_SIZE: usize = 2_619_392;

    /// The acquired data, regenerated: 4 KiB blocks, every fourth one zero, the rest a
    /// repeating byte pattern that changes from block to block.
    pub(crate) fn pattern() -> Vec<u8> {
        (0..IMAGE_SIZE)
            .map(|i| {
                let block = i >> 12;
                if block % 4 == 3 {
                    0
                } else {
                    (i + block * 7) as u8
                }
            })
            .collect()
    }

    fn gunzip(path: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(fs::File::open(path).unwrap()).read_to_end(&mut out).unwrap();
        out
    }

    /// The three-segment uncompressed image, decompressed into `dir`.
    fn unpack_multi(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        for n in 1..=3 {
            let name = format!("multi.E0{n}");
            fs::write(dir.join(&name), gunzip(&fixture_dir().join(format!("{name}.gz")))).unwrap();
        }
        dir.join("multi.E01")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nixcavate-ewf-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn check_whole(ewf: &Ewf, expected: &[u8]) {
        assert_eq!(ewf.size(), expected.len() as u64);
        let mut all = vec![0u8; expected.len()];
        ewf.read_at(0, &mut all).unwrap();
        assert!(all == expected, "whole-image read differs");
        // Awkward pieces: straddling 32 KiB chunk edges, tiny reads, and the very end.
        for (offset, len) in [(32767, 2), (32768 * 5 - 100, 40000), (1, 100_000), (expected.len() - 1, 1), (0, 0)] {
            let mut buf = vec![0u8; len];
            ewf.read_at(offset as u64, &mut buf).unwrap();
            assert!(buf == expected[offset..offset + len], "read at {offset}+{len}");
        }
        assert!(ewf.read_at(expected.len() as u64 - 1, &mut [0u8; 2]).is_err());
        assert!(ewf.read_at(u64::MAX, &mut [0u8; 2]).is_err());
    }

    #[test]
    fn compressed_single_segment_matches_the_raw_image() {
        let ewf = Ewf::open(&fixture_dir().join("best.E01")).unwrap();
        check_whole(&ewf, &pattern());
    }

    #[test]
    fn small_chunks_and_encase5_layout() {
        let ewf = Ewf::open(&fixture_dir().join("small-chunks.E01")).unwrap();
        assert_eq!(ewf.chunk_size, 16 * 512);
        check_whole(&ewf, &pattern());
    }

    #[test]
    fn uncompressed_multi_segment_matches_across_segment_boundaries() {
        let dir = scratch("multi");
        let ewf = Ewf::open(&unpack_multi(&dir)).unwrap();
        assert_eq!(ewf.segments.len(), 3);
        let expected = pattern();
        check_whole(&ewf, &expected);
        // Every chunk that starts a segment, plus a read across each segment join.
        let mut firsts: Vec<u64> = Vec::new();
        for (i, chunk) in ewf.chunks.iter().enumerate() {
            if i == 0 || chunk.segment != ewf.chunks[i - 1].segment {
                firsts.push(i as u64 * ewf.chunk_size);
            }
        }
        assert_eq!(firsts.len(), 3);
        for first in &firsts[1..] {
            let mut buf = vec![0u8; 70000];
            let start = first - 35000;
            ewf.read_at(start, &mut buf).unwrap();
            assert!(buf == expected[start as usize..start as usize + 70000]);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_segment_is_an_error() {
        let dir = scratch("missing");
        let first = unpack_multi(&dir);
        fs::remove_file(dir.join("multi.E03")).unwrap();
        let err = Ewf::open(&first).err().unwrap();
        assert!(err.to_string().contains("missing"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn segment_names() {
        let name = |first: &str, n| segment_path(Path::new(first), n).map(|p| p.to_string_lossy().into_owned());
        assert_eq!(name("/x/a.E01", 2).as_deref(), Some("/x/a.E02"));
        assert_eq!(name("/x/a.E01", 99).as_deref(), Some("/x/a.E99"));
        assert_eq!(name("/x/a.E01", 100).as_deref(), Some("/x/a.EAA"));
        assert_eq!(name("/x/a.E01", 126).as_deref(), Some("/x/a.EBA"));
        assert_eq!(name("/x/a.e01", 100).as_deref(), Some("/x/a.eaa"));
        assert_eq!(name("/x/a.E01", 100 + 676).as_deref(), Some("/x/a.FAA"));
        assert_eq!(name("/x/a.dd", 2), None);
    }

    #[test]
    fn ex01_is_unsupported() {
        let mut data = b"EVF2\x0d\x0a\x81\x00".to_vec();
        data.resize(64, 0);
        let err = Ewf::from_segments(vec![Box::new(data)]).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("Ex01"));
    }

    #[test]
    fn truncated_and_flipped_images_never_panic() {
        let data = fs::read(fixture_dir().join("best.E01")).unwrap();
        let expected = pattern();
        let exercise = |bytes: Vec<u8>| {
            if let Ok(ewf) = Ewf::from_segments(vec![Box::new(bytes)]) {
                let mut buf = vec![0u8; 100_000];
                for offset in (0..ewf.size()).step_by(65_536) {
                    let n = buf.len().min((ewf.size() - offset) as usize);
                    if ewf.read_at(offset, &mut buf[..n]).is_ok() {
                        // A read that succeeds must be right: checksums catch the rest.
                        assert!(buf[..n] == expected[offset as usize..offset as usize + n]);
                    }
                }
            }
        };
        for len in (0..data.len()).step_by(97) {
            exercise(data[..len].to_vec());
        }
        // Metadata at the front and the tail (tables, volume, done) is flipped densely;
        // the middle holds chunk data, sampled more sparsely.
        let mut targets: Vec<usize> = (0..1900).step_by(2).collect();
        targets.extend((data.len() - 2400..data.len()).step_by(2));
        targets.extend((1900..data.len() - 2400).step_by(211));
        for i in targets {
            for mask in [0x01u8, 0x80] {
                let mut flipped = data.clone();
                flipped[i] ^= mask;
                exercise(flipped);
            }
        }
    }

    #[test]
    fn a_damaged_table_is_replaced_by_its_mirror() {
        let mut data = fs::read(fixture_dir().join("best.E01")).unwrap();
        // The `table` section's descriptor is at 40627; its first body byte is the entry count.
        assert_eq!(&data[40627..40632], b"table");
        data[40627 + DESCRIPTOR_LEN] ^= 0x04;
        let ewf = Ewf::from_segments(vec![Box::new(data)]).unwrap();
        check_whole(&ewf, &pattern());
    }

    #[test]
    fn a_flipped_byte_in_a_raw_chunk_fails_only_that_chunk() {
        let dir = scratch("flip");
        let first = unpack_multi(&dir);
        let mut segment = fs::read(&first).unwrap();
        let ewf = Ewf::open(&first).unwrap();
        let hit = ewf.chunks[3].offset as usize + 10; // inside chunk 3 of segment 1
        drop(ewf);
        segment[hit] ^= 1;
        let mut segments: Vec<Segment> = vec![Box::new(segment)];
        for n in 2..=3 {
            segments.push(Box::new(fs::read(dir.join(format!("multi.E0{n}"))).unwrap()));
        }
        let ewf = Ewf::from_segments(segments).unwrap();
        let expected = pattern();
        let mut buf = vec![0u8; 100];
        ewf.read_at(2 * 32768, &mut buf).unwrap();
        assert!(buf == expected[2 * 32768..2 * 32768 + 100]);
        let err = ewf.read_at(3 * 32768 + 5, &mut buf).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    /// A section: descriptor (type, next, size, padding, Adler-32) and body.
    fn section(kind: &[u8], at: usize, body: &[u8], last: bool) -> Vec<u8> {
        let size = DESCRIPTOR_LEN + body.len();
        let mut out = kind.to_vec();
        out.resize(16, 0);
        out.extend_from_slice(&(if last { at } else { at + size } as u64).to_le_bytes());
        out.extend_from_slice(&(size as u64).to_le_bytes());
        out.resize(72, 0);
        out.extend_from_slice(&adler32(&out).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A table body with entries `offsets` relative to `base`, all compressed.
    fn table(base: u64, offsets: &[u32]) -> Vec<u8> {
        let mut out = (offsets.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&base.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&adler32(&out).to_le_bytes());
        offsets.iter().for_each(|o| out.extend_from_slice(&(o | 0x8000_0000).to_le_bytes()));
        out
    }

    /// One segment with one `sectors` section holding a single zero chunk of 32 KiB, followed
    /// by `tables` table sections that all point at that one chunk.
    fn shared_chunk(tables: usize) -> Vec<u8> {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(&[0u8; 32768]).unwrap();
        let chunk = z.finish().unwrap();
        let mut f = SIGNATURE.to_vec();
        f.extend_from_slice(&[1, 1, 0, 0, 0]);
        let mut volume = vec![0u8; 1052];
        volume[4..8].copy_from_slice(&(tables as u32).to_le_bytes());
        volume[8..12].copy_from_slice(&64u32.to_le_bytes());
        volume[12..16].copy_from_slice(&512u32.to_le_bytes());
        volume[16..24].copy_from_slice(&(tables as u64 * 64).to_le_bytes());
        f.extend(section(b"volume", f.len(), &volume, false));
        let base = (f.len() + DESCRIPTOR_LEN) as u64;
        f.extend(section(b"sectors", f.len(), &chunk, false));
        for _ in 0..tables {
            f.extend(section(b"table", f.len(), &table(base, &[0]), false));
        }
        f.extend(section(b"done", f.len(), &[], true));
        f
    }

    #[test]
    fn tables_that_share_chunks_are_refused() {
        // 100 tables, one chunk: a 1 KB file that would present 3 MiB of image (or, with
        // 30,000 tables and 32 MiB chunks, 1 TB).
        assert!(Ewf::from_segments(vec![Box::new(shared_chunk(1))]).is_ok());
        let err = Ewf::from_segments(vec![Box::new(shared_chunk(100))]).err().expect("shared chunks accepted");
        assert!(err.to_string().contains("chunk"), "{err}");
    }

    #[test]
    fn chunks_above_16_mib_are_refused() {
        let data = fs::read(fixture_dir().join("best.E01")).unwrap();
        let body = 663 + DESCRIPTOR_LEN;
        let with_sectors_per_chunk = |spc: u32| {
            let mut data = data.clone();
            data[body + 8..body + 12].copy_from_slice(&spc.to_le_bytes());
            Ewf::from_segments(vec![Box::new(data)])
        };
        assert!(with_sectors_per_chunk(32768).is_ok(), "16 MiB chunks, ewfacquire's largest");
        assert!(with_sectors_per_chunk(65536).is_err(), "32 MiB chunks");
    }

    #[test]
    fn forged_geometry_is_refused() {
        let mut data = fs::read(fixture_dir().join("best.E01")).unwrap();
        // The volume section's body starts after its 76-byte descriptor at offset 663.
        let body = 663 + DESCRIPTOR_LEN;
        data[body + 8..body + 12].copy_from_slice(&u32::MAX.to_le_bytes()); // sectors per chunk
        assert!(Ewf::from_segments(vec![Box::new(data)]).is_err());
    }
}

//! VMware VMDK reader, written from VMware's "Virtual Disk Format 1.1" specification.
//!
//! A VMDK is a text descriptor naming extents, or a sparse extent file that embeds one:
//!
//! * `# Disk DescriptorFile`: `CID`, `parentCID`, `createType` and one line per extent,
//!   `RW <sectors> <FLAT|SPARSE|ZERO|VMFS> "<file>" [<offset>]`. Extents are laid end to end.
//!   FLAT (and ESXi's `VMFS`, a plain preallocated file) extents are raw files; SPARSE ones are
//!   `KDMV` files.
//! * `KDMV` hosted sparse extent: a 512-byte header (little endian; capacity, grain size and
//!   grain table entries per table, grain directory offset), a grain directory of u32 sector
//!   numbers of grain tables, and grain tables of u32 sector numbers of grains. 0 is an
//!   unallocated grain (zeros, as no parent is allowed) and 1 an explicitly zeroed one. The
//!   redundant directory is ignored. `streamOptimized` extents hold zlib-compressed grains,
//!   each preceded by a marker (u64 sector, u32 size), and put the directory at the end: the
//!   header then says so and the real one is the footer copy 1024 bytes before the end.
//!
//! Extent file names come from evidence, so only their last component is used and only in the
//! descriptor's own directory; absolute names and `..` are refused, and a symbolic link is
//! never followed. A missing extent is one warning, and reads in its range fail.
//!
//! Refused with the reason: a parent (`parentCID` is not `ffffffff`: a snapshot or linked
//! clone), ESXi delta and raw-device extents (`VMFSSPARSE`, `SESPARSE`, `VMFSRDM`, `VMFSRAW`).

use super::vdisk::{bad, for_blocks, map_data, printable, refuse, slice, BlockCache, Data, Disk};
use nixcavate_fs::{le16, le32, le64, ReadAt};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NAME: &str = "VMDK";
const SECTOR: u64 = 512;
/// A descriptor is a few hundred bytes; this much is generous.
const MAX_DESCRIPTOR: usize = 1 << 20;
/// Extents per disk. A 2 GiB-split disk of 16 TiB has 8192.
const MAX_EXTENTS: usize = 8192;
const HEADER_LEN: usize = 512;
const GD_AT_END: u64 = u64::MAX;
const FLAG_NEWLINE_CHECK: u32 = 1;
const FLAG_COMPRESSED: u32 = 1 << 16;
/// Grain sizes accepted, in sectors: the specification's minimum of 8 (4 KiB) to 16 MiB.
const GRAIN_SECTORS: std::ops::RangeInclusive<u64> = 8..=32768;
const MAX_GTES: u64 = 1 << 16;

struct Sparse {
    file: Data,
    /// Grain size in bytes.
    grain: u64,
    gtes: u64,
    gd_offset: u64,
    gd_entries: u64,
    compressed: bool,
    /// Capacity in bytes.
    capacity: u64,
}

enum Kind {
    Zero,
    /// `None`: the file is missing.
    Flat(Option<Data>, u64),
    Sparse(Sparse),
}

struct Extent {
    /// Where the extent starts in the disk.
    start: u64,
    len: u64,
    kind: Kind,
}

pub struct Vmdk {
    extents: Vec<Extent>,
    size: u64,
    cache: BlockCache,
}

pub fn open(path: &Path, head: &[u8]) -> io::Result<Disk> {
    if head.starts_with(b"KDMV") {
        return from_sparse(map_data(path)?);
    }
    let mut notes = Vec::new();
    let (extents, kind) = {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_DESCRIPTOR as u64 {
            return Err(bad(NAME, "the descriptor file is too large"));
        }
        let text = std::fs::read(path)?;
        (descriptor_extents(&text, path.parent().unwrap_or(Path::new(".")), &mut notes)?, "descriptor")
    };
    Ok(finish(extents, kind, notes))
}

/// A disk that is one sparse extent file (a `monolithicSparse` or `streamOptimized` VMDK).
pub fn from_sparse(file: Data) -> io::Result<Disk> {
    let mut notes = Vec::new();
    let sparse = sparse_extent(file, &mut notes)?;
    let len = sparse.capacity;
    Ok(finish(vec![Extent { start: 0, len, kind: Kind::Sparse(sparse) }], "sparse extent file", notes))
}

fn finish(extents: Vec<Extent>, kind: &str, mut notes: Vec<String>) -> Disk {
    let size = extents.last().map_or(0, |e| e.start + e.len);
    let grain = extents
        .iter()
        .filter_map(|e| match &e.kind {
            Kind::Sparse(s) => Some(s.grain),
            _ => None,
        })
        .max()
        .unwrap_or(1);
    notes.insert(0, format!("VMDK virtual disk read directly ({kind}): {size} bytes in {} extent(s)", extents.len()));
    Disk { reader: Arc::new(Vmdk { extents, size, cache: BlockCache::new(grain) }), notes }
}

/// Parses the descriptor in `text`: refuses parents and unsupported extents, opens the rest.
fn descriptor_extents(text: &[u8], dir: &Path, notes: &mut Vec<String>) -> io::Result<Vec<Extent>> {
    let text = String::from_utf8_lossy(text);
    let (mut parent_cid, mut parent_hint) = (None, None);
    let mut lines = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        if let Some((key, value)) = line.split_once('=') {
            let (key, value) = (key.trim(), value.trim().trim_matches('"'));
            match key {
                "parentCID" => parent_cid = Some(value.to_ascii_lowercase()),
                "parentFileNameHint" => parent_hint = Some(printable(value)),
                _ => {}
            }
        } else if ["RW ", "RDONLY ", "NOACCESS "].iter().any(|p| line.starts_with(p)) {
            lines.push(line);
        }
    }
    if parent_cid.is_some_and(|cid| cid != "ffffffff") {
        return Err(refuse(
            NAME,
            format!(
                "the disk has a parent ({}): it is a snapshot or linked clone; consolidate it first",
                parent_hint.as_deref().unwrap_or("not named")
            ),
        ));
    }
    if lines.is_empty() {
        return Err(bad(NAME, "the descriptor lists no extents"));
    }
    if lines.len() > MAX_EXTENTS {
        return Err(bad(NAME, format!("the descriptor lists more than {MAX_EXTENTS} extents")));
    }
    let (mut extents, mut start) = (Vec::new(), 0u64);
    let mut problems: Vec<String> = Vec::new();
    for line in lines {
        let (access, sectors, kind, name, offset) = parse_extent(line)?;
        if access == "NOACCESS" {
            return Err(refuse(NAME, "an extent is marked NOACCESS"));
        }
        let len = sectors
            .checked_mul(SECTOR)
            .filter(|&l| l <= i64::MAX as u64)
            .ok_or_else(|| bad(NAME, "implausible extent size"))?;
        let found = |name: &str| resolve(dir, name);
        let extent_kind = match kind.as_str() {
            "ZERO" => Kind::Zero,
            "FLAT" | "VMFS" => {
                let name = name.ok_or_else(|| bad(NAME, "a FLAT extent has no file name"))?;
                match found(&name)? {
                    Some(path) => {
                        let data = map_data(&path)?;
                        let have = (*data).as_ref().len() as u64;
                        let off = offset.checked_mul(SECTOR).ok_or_else(|| bad(NAME, "implausible extent offset"))?;
                        if off.checked_add(len).is_none_or(|end| end > have) {
                            problems.push(format!(
                                "{} is shorter than the {len} bytes the descriptor gives it",
                                printable(&name)
                            ));
                        }
                        Kind::Flat(Some(data), off)
                    }
                    None => {
                        problems.push(format!("{} is missing", printable(&name)));
                        Kind::Flat(None, 0)
                    }
                }
            }
            "SPARSE" => {
                let name = name.ok_or_else(|| bad(NAME, "a SPARSE extent has no file name"))?;
                match found(&name)? {
                    Some(path) => {
                        let sparse = sparse_extent(map_data(&path)?, notes)
                            .map_err(|e| io::Error::new(e.kind(), format!("{e} (extent {})", printable(&name))))?;
                        if sparse.capacity != len {
                            return Err(bad(
                                NAME,
                                format!(
                                    "extent {} holds {} bytes, the descriptor says {len}",
                                    printable(&name),
                                    sparse.capacity
                                ),
                            ));
                        }
                        Kind::Sparse(sparse)
                    }
                    None => {
                        problems.push(format!("{} is missing", printable(&name)));
                        Kind::Flat(None, 0)
                    }
                }
            }
            "VMFSSPARSE" | "SESPARSE" => {
                return Err(refuse(
                    NAME,
                    format!("an extent is an ESXi snapshot delta ({kind}); consolidate the snapshots first"),
                ));
            }
            "VMFSRDM" | "VMFSRAW" => {
                return Err(refuse(
                    NAME,
                    format!("an extent is a raw device mapping ({kind}) with no data in the files"),
                ));
            }
            other => return Err(refuse(NAME, format!("extent type {} is not supported", printable(other)))),
        };
        if len > 0 {
            extents.push(Extent { start, len, kind: extent_kind });
            start = start
                .checked_add(len)
                .filter(|&s| s <= i64::MAX as u64)
                .ok_or_else(|| bad(NAME, "implausible disk size"))?;
        }
    }
    if !problems.is_empty() {
        let shown: Vec<_> = problems.iter().take(3).cloned().collect();
        notes.push(format!(
            "{NAME}: {} extent problem(s), reads of those ranges fail: {}{}",
            problems.len(),
            shown.join("; "),
            if problems.len() > 3 { "; ..." } else { "" }
        ));
    }
    Ok(extents)
}

/// `(access, sectors, type, file name, offset in sectors)` of an extent line.
fn parse_extent(line: &str) -> io::Result<(String, u64, String, Option<String>, u64)> {
    let mut parts = line.splitn(4, char::is_whitespace);
    let access = parts.next().unwrap_or_default().to_string();
    let sectors = parts.next().and_then(|s| s.parse::<u64>().ok());
    let kind = parts.next().unwrap_or_default().to_ascii_uppercase();
    let (Some(sectors), false) = (sectors, kind.is_empty()) else {
        return Err(bad(NAME, format!("cannot read the extent line {}", printable(line))));
    };
    let rest = parts.next().unwrap_or_default().trim();
    let (name, tail) = match rest.strip_prefix('"') {
        Some(quoted) => match quoted.split_once('"') {
            Some((name, tail)) => (Some(name.to_string()), tail),
            None => return Err(bad(NAME, format!("unterminated file name in {}", printable(line)))),
        },
        None => (None, rest),
    };
    let offset = tail.split_whitespace().next().and_then(|o| o.parse::<u64>().ok()).unwrap_or(0);
    Ok((access, sectors, kind, name, offset))
}

/// The file `name` (an evidence-supplied extent name) in `dir`: only its last component, and
/// only a regular file. `Ok(None)` when it is not there; an error for absolute names and `..`.
fn resolve(dir: &Path, name: &str) -> io::Result<Option<PathBuf>> {
    let drive = name.as_bytes().get(1) == Some(&b':') && name.as_bytes()[0].is_ascii_alphabetic();
    if name.starts_with('/') || name.starts_with('\\') || drive || name.contains('\0') {
        return Err(refuse(
            NAME,
            format!("the extent name {} is an absolute path; it is not followed", printable(name)),
        ));
    }
    let mut parts = name.split(['/', '\\']).filter(|p| !p.is_empty());
    if name.split(['/', '\\']).any(|p| p == "..") {
        return Err(refuse(
            NAME,
            format!("the extent name {} goes up a directory; it is not followed", printable(name)),
        ));
    }
    let Some(last) = parts.next_back().filter(|p| *p != ".") else {
        return Err(bad(NAME, "an extent has an empty file name"));
    };
    let regular = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    let exact = dir.join(last);
    if regular(&exact) {
        return Ok(Some(exact));
    }
    // Evidence copied from Windows or macOS may differ in case from the descriptor.
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(None) };
    for entry in entries.flatten().take(100_000) {
        if entry.file_name().to_string_lossy().eq_ignore_ascii_case(last) && regular(&entry.path()) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

/// Parses the sparse extent header of `file` (or its footer copy), and refuses what is refused.
fn sparse_extent(file: Data, notes: &mut Vec<String>) -> io::Result<Sparse> {
    let bytes: &[u8] = (*file).as_ref();
    let mut header = bytes.get(..HEADER_LEN).ok_or_else(|| bad(NAME, "the file is too short for a header"))?;
    if !header.starts_with(b"KDMV") {
        return Err(bad(NAME, "an extent is not a sparse extent file (no KDMV signature)"));
    }
    if le64(header, 56) == GD_AT_END {
        // streamOptimized: the directory offset is only in the footer, 1024 bytes before the end.
        let footer = bytes
            .len()
            .checked_sub(1024)
            .and_then(|at| bytes.get(at..at + HEADER_LEN))
            .filter(|f| f.starts_with(b"KDMV"))
            .ok_or_else(|| bad(NAME, "the grain directory is at the end but there is no footer"))?;
        header = footer;
    }
    let version = le32(header, 4);
    if !(1..=3).contains(&version) {
        return Err(refuse(NAME, format!("sparse extent version {version} is not supported")));
    }
    let flags = le32(header, 8);
    if flags & FLAG_NEWLINE_CHECK != 0 && header.get(73..77) != Some(b"\n \r\n") {
        return Err(bad(NAME, "the file was damaged by line-ending conversion (a text-mode transfer)"));
    }
    let capacity = le64(header, 12).checked_mul(SECTOR).filter(|&c| c <= i64::MAX as u64);
    let capacity = capacity.ok_or_else(|| bad(NAME, "implausible capacity"))?;
    let grain_sectors = le64(header, 20);
    if !GRAIN_SECTORS.contains(&grain_sectors) || !grain_sectors.is_power_of_two() {
        return Err(bad(NAME, format!("implausible grain size of {grain_sectors} sectors")));
    }
    let gtes = u64::from(le32(header, 44));
    if gtes == 0 || gtes > MAX_GTES {
        return Err(bad(NAME, format!("implausible grain table size of {gtes} entries")));
    }
    let compressed = flags & FLAG_COMPRESSED != 0;
    if compressed && le16(header, 77) != 1 {
        return Err(refuse(NAME, format!("compression algorithm {} is not supported", le16(header, 77))));
    }
    let grain = grain_sectors * SECTOR;
    let gd_entries = (capacity / SECTOR).div_ceil(grain_sectors * gtes);
    let gd_offset = le64(header, 56).checked_mul(SECTOR).ok_or_else(|| bad(NAME, "grain directory offset"))?;
    let gd_bytes = usize::try_from(gd_entries * 4).map_err(|_| bad(NAME, "grain directory size"))?;
    if slice(bytes, gd_offset, gd_bytes).is_none() {
        return Err(bad(NAME, "the grain directory lies outside the file"));
    }
    // An embedded descriptor may say the extent is a snapshot child.
    let (d_off, d_len) = (le64(header, 28), le64(header, 36));
    if d_off != 0 && d_len != 0 && d_len <= (MAX_DESCRIPTOR as u64) / SECTOR {
        if let Some(text) = d_off.checked_mul(SECTOR).and_then(|o| slice(bytes, o, (d_len * SECTOR) as usize)) {
            let text = String::from_utf8_lossy(text);
            let parent = text
                .lines()
                .filter_map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\0').split_once('='))
                .find(|(k, _)| k.trim() == "parentCID")
                .map(|(_, v)| v.trim().trim_matches('"').to_ascii_lowercase());
            if parent.is_some_and(|p| p != "ffffffff") {
                let hint = text
                    .lines()
                    .filter_map(|l| l.trim().split_once('='))
                    .find(|(k, _)| k.trim() == "parentFileNameHint")
                    .map(|(_, v)| printable(v.trim().trim_matches('"')));
                return Err(refuse(
                    NAME,
                    format!(
                        "the disk has a parent ({}): it is a snapshot or linked clone; consolidate it first",
                        hint.as_deref().unwrap_or("not named")
                    ),
                ));
            }
        }
    }
    if header.get(72).is_some_and(|&b| b != 0) {
        notes.push(format!(
            "{NAME}: the disk was not closed cleanly (unclean shutdown flag); its data are read as they are"
        ));
    }
    Ok(Sparse { file, grain, gtes, gd_offset, gd_entries, compressed, capacity })
}

impl Sparse {
    /// Reads `out` from the extent at `offset` (inside one grain, `start` being the grain's).
    fn read(&self, cache: &BlockCache, key: u64, start: u64, within: usize, out: &mut [u8]) -> io::Result<()> {
        let bytes: &[u8] = (*self.file).as_ref();
        let grain_index = start / self.grain;
        let (gd_index, gt_index) = (grain_index / self.gtes, grain_index % self.gtes);
        if gd_index >= self.gd_entries {
            return Err(bad(NAME, "grain beyond the directory"));
        }
        let gd =
            slice(bytes, self.gd_offset + gd_index * 4, 4).ok_or_else(|| bad(NAME, "grain directory is cut off"))?;
        let table = u64::from(le32(gd, 0));
        if table == 0 {
            out.fill(0);
            return Ok(());
        }
        let gt = table
            .checked_mul(SECTOR)
            .and_then(|t| slice(bytes, t + gt_index * 4, 4))
            .ok_or_else(|| bad(NAME, format!("the grain table at sector {table} lies outside the file")))?;
        let grain = u64::from(le32(gt, 0));
        if grain <= 1 {
            // 0 is unallocated and 1 a grain written as zeros.
            out.fill(0);
            return Ok(());
        }
        let at = grain * SECTOR;
        if !self.compressed {
            let src = slice(bytes, at + within as u64, out.len())
                .ok_or_else(|| bad(NAME, format!("the grain at sector {grain} lies outside the file")))?;
            out.copy_from_slice(src);
            return Ok(());
        }
        let data = cache.get((key, grain_index), || self.inflate(bytes, at, start))?;
        let part = data.get(within..within + out.len()).ok_or_else(|| bad(NAME, "short compressed grain"))?;
        out.copy_from_slice(part);
        Ok(())
    }

    /// The grain stored compressed at file offset `at`: u64 sector, u32 size, zlib data.
    fn inflate(&self, bytes: &[u8], at: u64, start: u64) -> io::Result<Vec<u8>> {
        let marker =
            slice(bytes, at, 12).ok_or_else(|| bad(NAME, format!("the grain at {at} lies outside the file")))?;
        let (lba, size) = (le64(marker, 0), le32(marker, 8) as u64);
        if size == 0 || lba.checked_mul(SECTOR) != Some(start) {
            return Err(bad(
                NAME,
                format!("the compressed grain at {at} does not belong to the grain it is mapped to"),
            ));
        }
        // A zlib stream is a little larger than its input in the worst case.
        if size > self.grain + (self.grain >> 4) + 1024 {
            return Err(bad(NAME, format!("the compressed grain at {at} is larger than a grain")));
        }
        let raw = slice(bytes, at + 12, size as usize)
            .ok_or_else(|| bad(NAME, format!("the compressed grain at {at} lies outside the file")))?;
        let expected = self.grain.min(self.capacity.saturating_sub(start)) as usize;
        let mut out = Vec::with_capacity(expected);
        flate2::read::ZlibDecoder::new(raw)
            .take(self.grain + 1)
            .read_to_end(&mut out)
            .map_err(|e| bad(NAME, format!("the compressed grain at {at}: {e}")))?;
        if out.len() as u64 > self.grain {
            return Err(bad(NAME, format!("the compressed grain at {at} inflates beyond the grain size")));
        }
        if out.len() < expected {
            return Err(bad(
                NAME,
                format!("the compressed grain at {at} inflated to {} of {expected} bytes", out.len()),
            ));
        }
        Ok(out)
    }
}

impl ReadAt for Vmdk {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.size).ok_or_else(super::vdisk::eof)?;
        let (mut position, mut done) = (offset, 0usize);
        while position < end {
            let index = self.extents.partition_point(|e| e.start <= position).saturating_sub(1);
            let extent = self.extents.get(index).ok_or_else(super::vdisk::eof)?;
            let inside = position - extent.start;
            let n = (extent.len - inside).min(end - position) as usize;
            let part = buf.get_mut(done..done + n).ok_or_else(super::vdisk::eof)?;
            match &extent.kind {
                Kind::Zero => part.fill(0),
                Kind::Flat(None, _) => return Err(bad(NAME, "the extent file for this range is missing")),
                Kind::Flat(Some(file), base) => {
                    let src = base
                        .checked_add(inside)
                        .and_then(|from| slice((**file).as_ref(), from, n))
                        .ok_or_else(|| bad(NAME, "the extent file is shorter than the descriptor says"))?;
                    part.copy_from_slice(src);
                }
                Kind::Sparse(sparse) => {
                    for_blocks(extent.len, sparse.grain, inside, part, |start, within, out| {
                        sparse.read(&self.cache, index as u64, start, within, out)
                    })?;
                }
            }
            position += n as u64;
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}

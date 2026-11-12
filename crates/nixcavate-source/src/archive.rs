//! Archives read in place: tar (plain or compressed) and zip.

use crate::{map, Entry, Store};
use memmap2::Mmap;
use nixcavate_core::time::secs_from_civil;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::sync::Arc;

/// A kept tar entry up to this size stays in memory; a larger one is spooled to scratch.
const MEMORY_ENTRY: u64 = 1 << 20;
/// Once this much is held in memory, every further kept entry is spooled.
const MEMORY_TOTAL: u64 = 512 << 20;
/// What an archive of `archive_len` bytes may keep in memory and scratch together: the
/// expansion limit times its size, at least 1 GiB. Sizes declared inside an archive are
/// attacker-controlled (a few kilobytes of tar or zip can claim terabytes), so what is kept
/// outside the archive is budgeted; entries past the budget are listed but not readable.
pub(crate) fn keep_budget(archive_len: u64) -> u64 {
    crate::expansion_budget(archive_len, 1 << 30)
}

/// Memory an xz stream may ask for. Real archives use a dictionary of at most 64 MiB.
const XZ_MEMORY: u64 = 256 << 20;

pub(crate) struct Listing {
    pub entries: Vec<Entry>,
    pub map: Arc<Mmap>,
    pub warnings: Vec<String>,
}

pub(crate) fn xz_decoder(data: &[u8]) -> io::Result<xz2::read::XzDecoder<&[u8]>> {
    let stream =
        xz2::stream::Stream::new_stream_decoder(XZ_MEMORY, xz2::stream::CONCATENATED).map_err(io::Error::other)?;
    Ok(xz2::read::XzDecoder::new_stream(data, stream))
}

pub(crate) fn open(path: &Path, keep: &dyn Fn(&str) -> bool, scratch: &Path) -> io::Result<Listing> {
    if fs::metadata(path)?.len() == 0 {
        return Err(io::Error::other("empty file"));
    }
    let map = Arc::new(map(path)?);
    let data: &[u8] = &map;
    let mut warnings = Vec::new();
    let entries = if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        zip_entries(data)?
    } else if data.starts_with(&[0x1f, 0x8b]) {
        tar_entries(flate2::read::MultiGzDecoder::new(data), None, keep, scratch, data.len() as u64, &mut warnings)?
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        tar_entries(zstd::stream::read::Decoder::new(data)?, None, keep, scratch, data.len() as u64, &mut warnings)?
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        tar_entries(xz_decoder(data)?, None, keep, scratch, data.len() as u64, &mut warnings)?
    } else if data.starts_with(b"BZh") && data.get(4..10) == Some(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]) {
        tar_entries(bzip2::read::MultiBzDecoder::new(data), None, keep, scratch, data.len() as u64, &mut warnings)?
    } else if data.get(257..262) == Some(b"ustar") {
        tar_entries(Cursor::new(data), Some(data.len()), keep, scratch, data.len() as u64, &mut warnings)?
    } else {
        return Err(io::Error::other("not a directory, disk image, tar or zip archive"));
    };
    Ok(Listing { entries, map, warnings })
}

/// Lists a tar stream. `mapped_len` is set for a plain tar, whose entries are then served as
/// ranges of the mapped file instead of being copied.
fn tar_entries(
    reader: impl Read,
    mapped_len: Option<usize>,
    keep: &dyn Fn(&str) -> bool,
    scratch: &Path,
    archive_len: u64,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<Entry>> {
    let budget = keep_budget(mapped_len.map_or(archive_len, |len| len as u64));
    let mut entries = Vec::new();
    // (index of the link entry, archive path of its target)
    let mut hard_links = Vec::new();
    let (mut in_memory, mut kept, mut spooled, mut over_budget) = (0u64, 0u64, 0usize, 0u64);
    let mut archive = tar::Archive::new(reader);
    for item in archive.entries()? {
        let mut item = item?;
        let header = item.header();
        let kind = header.entry_type();
        let path = item.path()?.to_string_lossy().trim_start_matches("./").trim_matches('/').to_string();
        let mut entry = Entry {
            path,
            size: item.size(),
            // Clamped: a forged time far in the future must not overflow later arithmetic.
            mtime: header.mtime().unwrap_or(0).min(MAX_MTIME) as i64,
            mode: header.mode().unwrap_or(0),
            uid: header.uid().unwrap_or(0) as u32,
            gid: header.gid().unwrap_or(0) as u32,
            link: None,
            store: Store::Dropped,
        };
        if kind.is_symlink() || kind.is_hard_link() {
            let Some(target) = item.link_name()? else { continue };
            let target = target.to_string_lossy();
            entry.size = 0;
            if kind.is_hard_link() {
                hard_links.push((entries.len(), target.trim_start_matches("./").trim_matches('/').to_string()));
            } else {
                entry.link = Some(target.into_owned());
            }
        } else if kind.is_file() || kind.is_contiguous() || kind.is_gnu_sparse() {
            let start = item.raw_file_position() as usize;
            let range = start..start.saturating_add(entry.size as usize);
            entry.store = match mapped_len {
                Some(len) if !kind.is_gnu_sparse() && range.end <= len => Store::Slice(range),
                _ if !keep(&entry.path) => Store::Dropped,
                _ if kept.saturating_add(entry.size) > budget => {
                    over_budget += 1;
                    Store::Dropped
                }
                _ if entry.size <= MEMORY_ENTRY && in_memory + entry.size <= MEMORY_TOTAL => {
                    let mut bytes = Vec::with_capacity(entry.size as usize);
                    item.read_to_end(&mut bytes)?;
                    in_memory += entry.size;
                    kept += entry.size;
                    Store::Memory(bytes.into())
                }
                _ => {
                    fs::create_dir_all(scratch)?;
                    let spool = scratch.join(format!("{spooled}.spool"));
                    spooled += 1;
                    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&spool)?;
                    kept += io::copy(&mut item, &mut file)?;
                    Store::File(spool)
                }
            };
        } else {
            continue;
        }
        entries.push(entry);
    }
    // A hard link names another member of the archive: it becomes a second name for the same
    // bytes. (A symlink target, by contrast, is a path on the collected host.)
    let by_path: HashMap<&str, usize> = entries.iter().enumerate().map(|(i, e)| (e.path.as_str(), i)).collect();
    let resolved: Vec<(usize, Option<usize>)> =
        hard_links.iter().map(|(link, target)| (*link, by_path.get(target.as_str()).copied())).collect();
    for (link, target) in resolved {
        if let Some(target) = target {
            entries[link].size = entries[target].size;
            entries[link].store = entries[target].store.clone();
        }
    }
    if over_budget > 0 {
        warnings.push(format!(
            "{over_budget} archive entries were not kept: together they expand past {} MiB, which is the \
             --max-expansion limit for this archive; raise it or pass 0 if the evidence is trusted",
            budget >> 20
        ));
    }
    Ok(entries)
}

/// 9999-12-31, in seconds: no real collection is newer.
const MAX_MTIME: u64 = 253_402_300_799;

/// Lists a zip from its central directory. Entries are read later straight from the mapped
/// file, so tasks decompress in parallel without sharing a reader.
fn zip_entries(data: &[u8]) -> io::Result<Vec<Entry>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).map_err(io::Error::other)?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let file = archive.by_index_raw(index).map_err(io::Error::other)?;
        if file.is_dir() {
            continue;
        }
        let Ok(name) = file.name() else { continue };
        let range = file.data_start().and_then(|start| {
            let start = usize::try_from(start).ok()?;
            let end = start.checked_add(usize::try_from(file.compressed_size()).ok()?)?;
            (end <= data.len()).then_some(start..end)
        });
        let store = match (range, file.compression(), file.encrypted()) {
            (Some(range), zip::CompressionMethod::Stored, false) => Store::Slice(range),
            (Some(range), zip::CompressionMethod::Deflated, false) => Store::Deflated(range),
            _ => Store::Dropped,
        };
        let mtime = file.last_modified().and_then(|t| {
            // Zip times are local with no zone; they are read as UTC, which is close enough
            // for their one use (inferring a log's year).
            secs_from_civil(
                t.year() as i64,
                t.month() as u32,
                t.day() as u32,
                t.hour() as u32,
                t.minute() as u32,
                t.second() as u32,
            )
        });
        let mut entry = Entry {
            path: name.trim_start_matches("./").trim_matches('/').to_string(),
            size: file.size(),
            mtime: mtime.unwrap_or(0),
            mode: file.unix_mode().unwrap_or(0),
            uid: 0,
            gid: 0,
            link: None,
            store,
        };
        if file.is_symlink() {
            // A zip symlink stores its target as the entry's content.
            let target = match &entry.store {
                Store::Slice(range) => Some(data[range.clone()].iter().take(4096).copied().collect::<Vec<u8>>()),
                Store::Deflated(range) => {
                    let mut out = Vec::new();
                    flate2::read::DeflateDecoder::new(&data[range.clone()])
                        .take(4096)
                        .read_to_end(&mut out)
                        .ok()
                        .map(|_| out)
                }
                _ => None,
            };
            let Some(target) = target else { continue };
            entry.link = Some(String::from_utf8_lossy(&target).into_owned());
            entry.size = 0;
            entry.store = Store::Dropped;
        }
        entries.push(entry);
    }
    Ok(entries)
}

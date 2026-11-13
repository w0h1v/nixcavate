//! Evidence access: one [`Source`] per directory, archive or single file, listed once and read
//! in place. Nothing here follows a symlink out of the evidence or opens a special file.

pub mod glob;
pub mod host;
pub mod plist;
pub mod tz;

mod archive;
mod dir;
mod image;

pub use glob::Pattern;
pub use host::{discover, Host, Os};
#[doc(hidden)]
pub use image::fuzz_raid;
pub use tz::Tz;

use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// How many times its own size compressed evidence may expand to; 0 means no limit.
static EXPANSION_LIMIT: AtomicU64 = AtomicU64::new(DEFAULT_EXPANSION_LIMIT);

/// Real logs and collections compress 5 to 30 times. Far beyond that is either a
/// decompression bomb or unusually repetitive data, and only a person can tell which.
pub const DEFAULT_EXPANSION_LIMIT: u64 = 100;

/// Sets the expansion limit for the whole process (`--max-expansion`). Call before any
/// evidence is opened.
pub fn set_expansion_limit(ratio: u64) {
    EXPANSION_LIMIT.store(ratio, Ordering::Relaxed);
}

/// The most that `compressed_len` bytes of compressed evidence may expand to: the limit
/// times its size, but never less than `floor`, so small files are not cut by rounding.
pub fn expansion_budget(compressed_len: u64, floor: u64) -> u64 {
    match EXPANSION_LIMIT.load(Ordering::Relaxed) {
        0 => u64::MAX,
        ratio => compressed_len.saturating_mul(ratio).max(floor),
    }
}

/// One file (or link) in a source.
#[derive(Debug)]
pub struct Entry {
    /// Path inside the source, `/`-separated, with no leading slash.
    pub path: String,
    pub size: u64,
    /// Modification time, seconds since the epoch. 0 when unknown.
    pub mtime: i64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The target, when this entry is a symbolic or hard link.
    pub link: Option<String>,
    store: Store,
}

/// Where an entry's bytes are.
#[derive(Clone, Debug)]
enum Store {
    File(PathBuf),
    /// A byte range of the mapped archive.
    Slice(Range<usize>),
    /// A raw-deflate range of the mapped archive (zip).
    Deflated(Range<usize>),
    Memory(Arc<[u8]>),
    /// A file inside a disk image: read through the filesystem reader.
    Volume {
        volume: usize,
        inode: u64,
        /// Bytes the filesystem allocated to the file.
        allocated: u64,
    },
    /// An archive entry no artifact asked for; its bytes were not kept.
    Dropped,
}

/// The bytes of one entry.
pub enum Data {
    Mapped(Mmap),
    Shared(Arc<Mmap>, Range<usize>),
    Memory(Arc<[u8]>),
    Owned(Vec<u8>),
}

impl Deref for Data {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Data::Mapped(map) => map,
            Data::Shared(map, range) => &map[range.clone()],
            Data::Memory(bytes) => bytes,
            Data::Owned(bytes) => bytes,
        }
    }
}

/// Maps a regular file read-only. Empty files cannot be mapped, so they become an empty buffer.
pub fn map_file(path: &Path) -> io::Result<Data> {
    if std::fs::metadata(path)?.len() == 0 {
        return Ok(Data::Owned(Vec::new()));
    }
    Ok(Data::Mapped(map(path)?))
}

/// The only `unsafe` in nixcavate.
#[allow(unsafe_code)]
pub(crate) fn map(path: &Path) -> io::Result<Mmap> {
    let file = File::open(path)?;
    // SAFETY: the mapping is read-only and private to this process. Evidence is static by
    // contract; if another process truncates the file mid-run the OS raises SIGBUS, which is
    // the documented trade-off of memory-mapped reads (docs/ARCHITECTURE.md).
    unsafe { Mmap::map(&file) }
}

/// A directory, archive or single file of evidence.
pub struct Source {
    pub path: PathBuf,
    /// Sorted by path.
    entries: Vec<Entry>,
    /// The archive file, for entries stored as ranges of it.
    map: Option<Arc<Mmap>>,
    /// The disk image, for entries stored as files of its volumes.
    image: Option<image::Image>,
    /// Where large compressed entries are inflated to before they are mapped.
    scratch: PathBuf,
    /// Bytes inflated to scratch so far, against the archive's keep budget.
    spooled: AtomicU64,
    spooled_files: AtomicU64,
    /// Problems found while listing (entries left out), for the caller to report.
    pub warnings: Vec<String>,
}

/// A deflated zip entry up to this size is inflated in memory; a larger one goes to scratch.
const INFLATE_IN_MEMORY: u64 = 64 << 20;

impl Source {
    /// Opens a directory or an archive (`.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`).
    ///
    /// Compressed tar streams cannot be re-read at random, so their entries are kept during
    /// this one pass: `keep` decides which (by path), small ones stay in memory and large
    /// ones are spooled to `scratch`. Other source kinds ignore both arguments.
    pub fn open(path: &Path, keep: &dyn Fn(&str) -> bool, scratch: &Path) -> io::Result<Source> {
        let (mut image, mut warnings) = (None, Vec::new());
        let (mut entries, map) = if path.is_dir() {
            (dir::walk(path)?, None)
        } else if let Some((entries, opened, notes)) = image::open(path, scratch)? {
            image = Some(opened);
            warnings = notes;
            (entries, None)
        } else {
            // Archives inside the archive that hold evidence are read after the listing.
            let keep = |path: &str| {
                keep(path) || archive::catscale_archive(path).is_some() || archive::wrapped_uac(path).is_some()
            };
            let listing = archive::open(path, &keep, scratch)?;
            warnings = listing.warnings;
            (listing.entries, listing.map)
        };
        // Velociraptor percent-encodes path characters such as `:`.
        if entries.iter().any(|e| e.path == "uploads.json" || e.path == "collection_context.json") {
            for entry in &mut entries {
                if entry.path.contains('%') {
                    entry.path = percent_decode(&entry.path);
                }
            }
        }
        let mut source = Source::from_entries(path, entries, map);
        source.image = image;
        source.scratch = scratch.to_path_buf();
        warnings.append(&mut source.warnings);
        source.warnings = warnings;
        // In a folder, an archive is a source of its own (the caller opens it).
        source.expand_nested(keep, !path.is_dir());
        Ok(source)
    }

    /// Adds the files of the archives inside the evidence that are known to hold a host's files:
    /// a CatScale collection's inner archives, as one host root `<output folder>/<host>/[root]`
    /// (a path that several of them hold is kept once), and, with `wrapped`, a UAC collection
    /// inside another archive.
    fn expand_nested(&mut self, keep: &dyn Fn(&str) -> bool, wrapped: bool) {
        // The CatScale archive of home directories does not name the host: the others do.
        let mut hosts = self.entries.iter().filter_map(|e| archive::catscale_archive(&e.path)).map(|(_, host)| host);
        let host = hosts.find(|h| !h.is_empty()).unwrap_or("catscale").to_string();
        let root_of = |path: &str| match archive::catscale_archive(path) {
            Some((folder, _)) => Some(format!("{folder}/{host}/[root]")),
            None => archive::wrapped_uac(path).filter(|_| wrapped).map(str::to_string),
        };
        let inner: Vec<(usize, String)> =
            self.entries.iter().enumerate().filter_map(|(i, e)| Some((i, root_of(&e.path)?))).collect();
        let mut added = Vec::new();
        for (nth, (i, root)) in inner.iter().enumerate() {
            let entry = &self.entries[*i];
            let scratch = self.scratch.join(format!("nested-{nth}"));
            let mut warnings = Vec::new();
            let listed = self.read(entry).and_then(|data| archive::nested_tar_gz(&data, keep, &scratch, &mut warnings));
            match listed {
                Ok(found) => added.extend(found.into_iter().map(|mut e| {
                    e.path = format!("{root}/{}", e.path);
                    e
                })),
                Err(e) => warnings.push(format!("not read: {e}")),
            }
            let path = entry.path.clone();
            self.warnings.extend(warnings.into_iter().map(|w| format!("{path}: {w}")));
        }
        // CatScale writes command output to `<folder>/<Section>/<file>.txt`. The host's root is
        // `<folder>/<host>/[root]`, so the sections move next to it, where artifacts reach them
        // with `../<Section>/...` as they reach UAC's `live_response/`.
        let folders: HashSet<String> = inner
            .iter()
            .filter_map(|(i, _)| Some(archive::catscale_archive(&self.entries[*i].path)?.0.to_string()))
            .collect();
        for entry in &mut self.entries {
            let moved = entry.path.rsplit_once('/').and_then(|(dir, file)| {
                let (folder, section) = dir.rsplit_once('/')?;
                (folders.contains(folder) && !section.contains('['))
                    .then(|| format!("{folder}/{host}/{section}/{file}"))
            });
            if let Some(path) = moved {
                entry.path = path;
            }
        }
        if !added.is_empty() || !folders.is_empty() {
            self.entries.append(&mut added);
            // A stable sort keeps the first archive's copy of a path that several hold.
            self.entries.sort_by(|a, b| a.path.cmp(&b.path));
            self.entries.dedup_by(|later, first| later.path == first.path);
        }
    }

    /// A source holding one plain file, named by its file name.
    pub fn single_file(path: &Path) -> io::Result<Source> {
        let entry = dir::file_entry(path, path.file_name().unwrap_or_default().to_string_lossy().into_owned())?;
        Ok(Source::from_entries(path, vec![entry], None))
    }

    /// An in-memory source, for tests.
    pub fn from_memory(files: &[(&str, &[u8])]) -> Source {
        let entries = files.iter().map(|&(path, bytes)| Entry::memory(path, bytes.into(), 0)).collect();
        Source::from_entries(Path::new("memory"), entries, None)
    }

    /// Sorts the entries by path and keeps the first of entries that share a path, with a
    /// warning: a directory or image never lists a path twice, and a later archive member of
    /// the same name must not silently replace the first.
    fn from_entries(path: &Path, mut entries: Vec<Entry>, map: Option<Arc<Mmap>>) -> Source {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let listed = entries.len();
        let mut first_repeat = None;
        entries.dedup_by(|later, first| {
            let repeat = later.path == first.path;
            if repeat && first_repeat.is_none() {
                first_repeat = Some(later.path.clone());
            }
            repeat
        });
        let warnings = match first_repeat {
            Some(first) => vec![format!(
                "{} entries repeat the path of an earlier entry and were left out, the first at {first}",
                listed - entries.len()
            )],
            None => Vec::new(),
        };
        Source {
            path: path.to_path_buf(),
            entries,
            map,
            image: None,
            scratch: PathBuf::new(),
            spooled: AtomicU64::new(0),
            spooled_files: AtomicU64::new(0),
            warnings,
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.binary_search_by(|e| e.path.as_str().cmp(path)).ok().map(|i| &self.entries[i])
    }

    /// The entries below `dir` (`""` is the whole source), as an index range.
    pub(crate) fn range_under(&self, dir: &str) -> Range<usize> {
        if dir.is_empty() {
            return 0..self.entries.len();
        }
        let start = self.entries.partition_point(|e| e.path.as_str() < dir);
        let below = |e: &Entry| e.path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'));
        // Names such as `dir-x` or `dir.bak` sort between `dir` and `dir/`; skip them.
        let first = start + self.entries[start..].iter().take_while(|e| !below(e) && e.path.starts_with(dir)).count();
        let len = self.entries[first..].iter().take_while(|e| below(e)).count();
        first..first + len
    }

    /// Reads an entry. Links are not followed here; see [`Host::entry`].
    pub fn read(&self, entry: &Entry) -> io::Result<Data> {
        let shared = || self.map.clone().ok_or_else(|| io::Error::other("archive is not mapped"));
        match &entry.store {
            Store::File(path) => map_file(path),
            Store::Memory(bytes) => Ok(Data::Memory(bytes.clone())),
            Store::Volume { volume, inode, allocated } => {
                let image = self.image.as_ref().ok_or_else(|| io::Error::other("disk image is not open"))?;
                Ok(Data::Owned(image.read(*volume, *inode, entry.size, *allocated)?))
            }
            Store::Slice(range) => Ok(Data::Shared(shared()?, range.clone())),
            Store::Deflated(range) => {
                let map = shared()?;
                // The size comes from the archive's own directory, so it only bounds the read;
                // it is never trusted as an amount of memory to hold.
                let mut inflated = flate2::read::DeflateDecoder::new(&map[range.clone()]).take(entry.size);
                if entry.size <= INFLATE_IN_MEMORY {
                    let mut out = Vec::new();
                    inflated.read_to_end(&mut out)?;
                    return Ok(Data::Owned(out));
                }
                if self.spooled.fetch_add(entry.size, Ordering::Relaxed).saturating_add(entry.size)
                    > archive::keep_budget(map.len() as u64)
                {
                    return Err(io::Error::other(
                        "the archive's large entries expand past the --max-expansion limit; raise it or pass 0 if the evidence is trusted",
                    ));
                }
                std::fs::create_dir_all(&self.scratch)?;
                let name = format!("inflated-{}.spool", self.spooled_files.fetch_add(1, Ordering::Relaxed));
                let spool = self.scratch.join(name);
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&spool)?;
                io::copy(&mut inflated, &mut file)?;
                drop(file);
                map_file(&spool)
            }
            Store::Dropped => Err(io::Error::other(format!("{} was not kept from the archive", entry.path))),
        }
    }
}

impl Entry {
    pub(crate) fn memory(path: &str, bytes: Arc<[u8]>, mtime: i64) -> Entry {
        Entry {
            path: path.to_string(),
            size: bytes.len() as u64,
            mtime,
            mode: 0o644,
            uid: 0,
            gid: 0,
            link: None,
            store: Store::Memory(bytes),
        }
    }

    /// The file name: the last path segment.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
            // A decoded `/` would change the path's shape, so `%2F` stays encoded.
            (b'%', Some(hi), Some(lo)) if (hi * 16 + lo) as u8 != b'/' => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (b, ..) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_under_skips_sibling_names() {
        let source = Source::from_memory(&[
            ("a/x", b""),
            ("root", b""),
            ("root-old/etc/passwd", b""),
            ("root.bak", b""),
            ("root/etc/passwd", b""),
            ("root/var/log/syslog", b""),
            ("rooz", b""),
        ]);
        let paths = |dir| source.entries()[source.range_under(dir)].iter().map(|e| e.path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths("root"), ["root/etc/passwd", "root/var/log/syslog"]);
        assert_eq!(paths("a"), ["a/x"]);
        assert_eq!(paths("missing"), Vec::<&str>::new());
        assert_eq!(paths("").len(), 7);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("uploads/auto/C%3A/x"), "uploads/auto/C:/x");
        assert_eq!(percent_decode("a%2Fb"), "a%2Fb");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn reads_memory_entries() {
        let source = Source::from_memory(&[("etc/hostname", b"web01\n")]);
        let entry = source.entry("etc/hostname").unwrap();
        assert_eq!(&*source.read(entry).unwrap(), b"web01\n");
        assert!(source.entry("etc/host").is_none());
    }
}

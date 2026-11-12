//! Read-only filesystem readers for disk images.
//!
//! Each reader takes a [`ReadAt`] (the bytes of one partition) and gives back a [`Volume`]:
//! a way to list every file with its metadata and to read a file's content. Nothing here
//! writes, mounts, or trusts the image: every offset, length and count read from disk is
//! bounds-checked. Every walk runs through one shared loop that lists each directory inode at
//! most once and bounds nesting depth, path length and the number of nodes and path bytes it
//! reports, and that refuses entry names a path cannot hold. Structures inside one file
//! (extent trees, B-trees) are bounded by their depth and by refusing a block reached twice;
//! each reader's module documentation says how.
//!
//! The crate has no dependencies. It is the part of nixcavate most exposed to hostile input
//! and is fuzzed on its own.

pub mod apfs;
pub mod ext4;
pub mod xfs;

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;

/// Random access to the bytes of an image or partition.
pub trait ReadAt: Sync {
    /// Fills `buf` from `offset`. Reading past the end is an error.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Total size in bytes.
    fn size(&self) -> u64;
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        (**self).size()
    }
}

impl<T: ReadAt + Send + ?Sized> ReadAt for Arc<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        (**self).size()
    }
}

/// An image held in memory, usually a memory-mapped raw image.
pub struct Bytes<'a>(pub &'a [u8]);

impl ReadAt for Bytes<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).ok();
        let source = start.and_then(|s| self.0.get(s..s.checked_add(buf.len())?));
        match source {
            Some(source) => {
                buf.copy_from_slice(source);
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the image")),
        }
    }

    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

/// A window onto part of another [`ReadAt`]: one partition of a disk.
#[derive(Clone)]
pub struct Slice<R> {
    pub inner: R,
    pub start: u64,
    pub len: u64,
}

impl<R: ReadAt> ReadAt for Slice<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64);
        match end {
            Some(end) if end <= self.len => self.inner.read_at(self.start + offset, buf),
            _ => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the partition")),
        }
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// The `N` bytes at `at`, zeros when `b` is too short (an overflowing `at + N` makes an empty
/// range, which `get` refuses).
fn array<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    match b.get(at..at.wrapping_add(N)) {
        Some(s) if s.len() == N => {
            let mut out = [0; N];
            out.copy_from_slice(s);
            out
        }
        _ => [0; N],
    }
}

/// Integers at a byte offset of on-disk data, 0 when `b` is too short to hold them.
pub fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(array(b, at))
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(array(b, at))
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(array(b, at))
}

pub fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(array(b, at))
}

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(array(b, at))
}

pub fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(array(b, at))
}

/// Adler-32 (RFC 1950), the checksum of zlib streams and of EWF sections.
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(5552) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    b << 16 | a
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The image does not follow the filesystem's format.
    Corrupt(String),
    /// The image uses a feature this reader does not implement (encryption, a newer version).
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Corrupt(msg) => write!(f, "corrupt filesystem: {msg}"),
            Error::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    /// Devices, sockets and FIFOs: listed, never read.
    Other,
}

/// One file as the filesystem records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Path from the volume root, `/`-separated, with no leading slash.
    pub path: String,
    pub inode: u64,
    pub kind: Kind,
    /// Unix mode bits, including the file type bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Bytes the filesystem has allocated to the file (data blocks and the blocks that map
    /// them), as it records them: less than `size` for a sparse file. See [`worth_reading`].
    pub allocated: u64,
    pub links: u32,
    /// Times in nanoseconds since the Unix epoch. `None` when the filesystem has no such
    /// time (ext3 has no creation time) or stores zero.
    pub accessed: Option<i64>,
    pub modified: Option<i64>,
    pub changed: Option<i64>,
    pub created: Option<i64>,
    /// The target, for a symlink.
    pub link_target: Option<String>,
}

/// An opened filesystem.
pub trait Volume: Sync {
    /// The filesystem name: `ext4`, `xfs`, `apfs`.
    fn kind(&self) -> &'static str;

    /// Calls `visit` once for every file, directory and link reachable from the root, within
    /// the limits below. A damaged directory is skipped and reported through `warn`; the walk
    /// continues.
    fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> Result<()>;

    /// Reads file content at `offset` into `buf` and returns the number of bytes read
    /// (less than `buf.len()` only at the end of the file). Sparse regions read as zeros.
    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// Longest path, and longest symlink target, a walk reports: Linux's `PATH_MAX`.
pub const MAX_PATH: usize = 4096;
/// Deepest directory nesting a walk descends into.
pub const MAX_DEPTH: usize = 256;
/// Most nodes one walk reports. The caller keeps one listing entry per node, about 120 bytes
/// plus its path, so 20 million nodes take about 2.4 GB before their paths: about what one
/// host can hold, and more than the largest real volumes have.
pub const MAX_NODES: u64 = 20_000_000;
/// Most path and symlink-target bytes one walk reports. Real paths average well under 100
/// bytes, so 20 million nodes of real paths fit; crafted long paths (up to [`MAX_PATH`] each)
/// cannot add more than this.
pub const MAX_TEXT: u64 = 2 << 30;

/// Whether a file's whole content is worth reading into memory. A file larger than 64 MiB is
/// read only when at least a sixteenth of it is allocated: a sparse file that large is not a
/// log or a database, and a forged size must not make every read commit gigabytes of zeros.
pub fn worth_reading(size: u64, allocated: u64) -> bool {
    size <= 64 << 20 || size / 16 <= allocated
}

/// A file's whole content, refusing sizes above `limit` so a forged size cannot exhaust memory.
pub fn read_all(volume: &dyn Volume, inode: u64, size: u64, limit: u64) -> Result<Vec<u8>> {
    if size > limit {
        return Err(Error::unsupported(format!("file of {size} bytes exceeds the {limit}-byte read limit")));
    }
    let mut out = vec![0u8; size as usize];
    let mut done = 0;
    while done < out.len() {
        let n = volume.read(inode, done as u64, &mut out[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    out.truncate(done);
    Ok(out)
}

/// The entries of one directory as a reader lists them: child inode numbers and raw names.
#[derive(Default)]
pub(crate) struct Entries {
    names: Vec<u8>,
    list: Vec<(u64, usize, usize)>,
    room: usize,
}

impl Entries {
    /// Adds an entry. Returns false when the walk can take no more: stop listing.
    pub(crate) fn push(&mut self, child: u64, name: &[u8]) -> bool {
        if self.list.len() >= self.room {
            return false;
        }
        self.list.push((child, self.names.len(), name.len()));
        self.names.extend_from_slice(name);
        true
    }

    pub(crate) fn full(&self) -> bool {
        self.list.len() >= self.room
    }
}

/// What a reader supplies to [`walk_tree`].
pub(crate) trait Tree {
    /// Lists directory `dir` (reached as `path`) into `out`, stopping when `out` is full.
    /// Entries listed before an error are kept. `.` and `..` records are left out.
    fn list(&mut self, dir: u64, path: &str, out: &mut Entries, warn: &mut dyn FnMut(String)) -> Result<()>;

    /// The node for `ino`, reached as `path`. Its `path` field is filled in by the walk.
    fn node(&mut self, ino: u64, path: &str, warn: &mut dyn FnMut(String)) -> Result<Node>;

    /// Whether the reader's work budget is spent: the walk ends with the next error.
    fn exhausted(&self) -> bool {
        false
    }
}

/// A path as warnings show it: from the root, and only its last 200 bytes when longer.
pub(crate) fn shown(path: &str) -> String {
    match path.char_indices().map(|(i, _)| i).find(|&i| path.len() - i <= 200) {
        Some(0) | None => format!("/{path}"),
        Some(i) => format!("/...{}", &path[i..]),
    }
}

/// The walk every reader runs: depth-first from `root`, each directory inode listed at most
/// once, nesting up to [`MAX_DEPTH`], paths up to [`MAX_PATH`] bytes, and at most
/// [`MAX_NODES`] nodes and [`MAX_TEXT`] bytes of paths and link targets. A name that is
/// empty, `.`, `..`, or holds `/` or NUL is skipped, and so is a name that reads the same as
/// an earlier one in its directory (after converting a non-UTF-8 name lossily). Every
/// warning starts with `fs`; reaching a limit ends the walk with a warning, not an error.
pub(crate) fn walk_tree(
    fs: &str,
    tree: &mut dyn Tree,
    root: u64,
    visit: &mut dyn FnMut(Node),
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let warn = &mut |m: String| warn(format!("{fs}: {m}"));
    let mut visited = HashSet::from([root]);
    let mut stack = vec![(root, String::new(), 0usize)];
    let mut entries = Entries::default();
    let (mut nodes, mut text) = (0u64, 0u64);
    while let Some((dir, path, depth)) = stack.pop() {
        entries.names.clear();
        entries.list.clear();
        entries.room = (MAX_NODES - nodes) as usize;
        if let Err(e) = tree.list(dir, &path, &mut entries, warn) {
            if tree.exhausted() {
                return Err(e);
            }
            warn(format!("{}: {e}", shown(&path)));
        }
        let (mut invalid, mut repeated, mut long) = (0usize, 0usize, 0usize);
        let mut names: HashSet<Cow<str>> = HashSet::with_capacity(entries.list.len());
        // A full listing means the node limit cut this directory short.
        let mut stopped = entries.full();
        for &(child, start, len) in &entries.list {
            let raw = &entries.names[start..start + len];
            if raw.is_empty() || raw == b"." || raw == b".." || raw.contains(&b'/') || raw.contains(&0) {
                invalid += 1;
                continue;
            }
            let name = String::from_utf8_lossy(raw);
            if path.len() + 1 + name.len() > MAX_PATH {
                long += 1;
                continue;
            }
            let mut child_path = String::with_capacity(path.len() + 1 + name.len());
            if !path.is_empty() {
                child_path.push_str(&path);
                child_path.push('/');
            }
            child_path.push_str(&name);
            if !names.insert(name) {
                repeated += 1;
                continue;
            }
            if nodes >= MAX_NODES || text >= MAX_TEXT {
                stopped = true;
                break;
            }
            let mut node = match tree.node(child, &child_path, warn) {
                Ok(node) => node,
                Err(e) => {
                    if tree.exhausted() {
                        return Err(e);
                    }
                    warn(format!("{}: {e}", shown(&child_path)));
                    continue;
                }
            };
            node.path = child_path;
            nodes += 1;
            text += (node.path.len() + node.link_target.as_ref().map_or(0, String::len)) as u64;
            if node.kind == Kind::Directory {
                if depth + 1 > MAX_DEPTH {
                    warn(format!("{}: directories nested too deep, not descending", shown(&node.path)));
                } else if !visited.insert(child) {
                    warn(format!("{}: directory inode {child} already listed, not descending", shown(&node.path)));
                } else {
                    stack.push((child, node.path.clone(), depth + 1));
                }
            }
            visit(node);
        }
        for (count, what) in [
            (invalid, "with an empty name, `.`, `..`, `/` or NUL"),
            (repeated, "repeating an earlier name"),
            (long, "with paths longer than 4096 bytes"),
        ] {
            if count > 0 {
                warn(format!("{}: {count} entries {what} skipped", shown(&path)));
            }
        }
        if stopped {
            warn(format!("walk stopped after {nodes} nodes and {text} bytes of paths: limit reached"));
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_are_bounded() {
        let image = Bytes(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let part = Slice { inner: &image, start: 2, len: 4 };
        let mut buf = [0u8; 4];
        part.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [3, 4, 5, 6]);
        assert!(part.read_at(1, &mut buf).is_err());
        assert!(part.read_at(u64::MAX, &mut buf).is_err());
        assert!(image.read_at(5, &mut buf).is_err());
        assert_eq!(part.size(), 4);
    }

    #[test]
    fn byte_helpers_read_zero_past_the_end() {
        let b = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!((le16(&b, 0), be16(&b, 0)), (0x0201, 0x0102));
        assert_eq!((le32(&b, 1), be32(&b, 1)), (0x0504_0302, 0x0203_0405));
        assert_eq!((le64(&b, 1), be64(&b, 1)), (0x0908_0706_0504_0302, 0x0203_0405_0607_0809));
        assert_eq!((le16(&b, 8), le32(&b, 6), le64(&b, 2), be64(&b, usize::MAX)), (0, 0, 0, 0));
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn the_read_rule() {
        assert!(worth_reading(64 << 20, 0));
        assert!(!worth_reading((64 << 20) + 1, 4096));
        assert!(worth_reading(1 << 30, 64 << 20));
        assert!(!worth_reading(1 << 30, (64 << 20) - 1));
    }
}

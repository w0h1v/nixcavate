//! Disk images as evidence: a raw image or an EWF (E01) set, split into partitions, each
//! partition opened as a filesystem [`Volume`] and listed like a directory.
//!
//! # Layout
//!
//! Every volume `p<partition index>` appears as
//!
//! ```text
//! p1/[root]/etc/passwd        the volume's files (host root = `p1/[root]`)
//! p1/bodyfile/bodyfile.txt    a synthesized Sleuth Kit body file of the whole volume
//! ```
//!
//! This mirrors UAC's `[root]` + `bodyfile/bodyfile.txt` layout, so nothing downstream is
//! special: host discovery finds `p1/[root]` through its `etc/passwd`, the `bodyfile` artifact's
//! `../bodyfile/bodyfile.txt` pattern (relative to the parent of the host root) matches, and a
//! `source_path` such as `p2/[root]/var/log/auth.log` says which partition a file came from.
//! The prefix is used even for a single volume, because a host root of `""` has no parent and
//! the `../` patterns could not match. A partition holding several volumes (an APFS container)
//! uses `p<index>v<n>`. The logical volumes of an LVM2 volume group are volumes of their own,
//! named `<vg>-<lv>` (restricted to `[A-Za-z0-9_.+-]`) instead of `p<index>`.
//!
//! # Ownership and memory
//!
//! The volumes own a shared handle on the image reader, so the [`Image`] keeps every volume
//! open for the whole run and a file read goes straight to its volume. Listing keeps one
//! [`Entry`] per file and link; body files are written to the scratch directory, and each
//! volume keeps its first [`WARNINGS_KEPT`] warnings plus a count of the rest.

mod ewf;
mod lvm;
mod partitions;

use crate::{map, Entry, Source, Store};
use memmap2::Mmap;
use nixcavate_fs::apfs::Apfs;
use nixcavate_fs::ext4::Ext4;
use nixcavate_fs::xfs::Xfs;
use nixcavate_fs::{read_all, worth_reading, Bytes, Kind, Node, ReadAt, Slice, Volume};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

pub use partitions::Partition;

/// The largest file read out of an image in one piece. Bigger files are skipped by the reader,
/// and so are large files that are mostly unallocated ([`worth_reading`]).
const READ_LIMIT: u64 = 2 << 30;
/// Warnings kept per volume; the rest are only counted.
const WARNINGS_KEPT: usize = 20;

/// The image reader, shared by every volume opened on it.
type Shared = Arc<dyn ReadAt + Send + Sync>;
/// One partition of the image.
type Part = Slice<Shared>;
type Opened = Box<dyn Volume + Send + Sync>;
/// What listing an image gives: its entries, its open volumes and the warnings.
type Listed = (Vec<Entry>, Image, Vec<String>);

/// The volumes of the image behind a [`Source`], open for its lifetime.
pub(crate) struct Image {
    volumes: Vec<Opened>,
}

impl Image {
    /// Reads the whole content of file `inode` from volume number `volume`.
    pub(crate) fn read(&self, volume: usize, inode: u64, size: u64, allocated: u64) -> io::Result<Vec<u8>> {
        let volume = self.volumes.get(volume).ok_or_else(|| io::Error::other("unknown volume"))?;
        if !worth_reading(size, allocated) {
            return Err(io::Error::other(format!(
                "a file of {size} bytes with only {allocated} allocated is not read whole"
            )));
        }
        read_all(&**volume, inode, size, READ_LIMIT).map_err(io::Error::other)
    }
}

/// A memory-mapped raw image.
struct Mapped(Mmap);

impl ReadAt for Mapped {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        Bytes(&self.0).read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

/// A raw image split into numbered pieces (`disk.001`, `disk.002`...), read as one disk.
struct Split {
    /// Each piece with the offset in the disk where it starts.
    pieces: Vec<(u64, Mmap)>,
    len: u64,
}

impl Split {
    /// The pieces that follow `first` when its extension is `000` or `001`: the same name with
    /// the next numbers, up to the first one that is missing. `None` when there are none.
    fn open(first: &Path) -> io::Result<Option<Split>> {
        let number = first.extension().and_then(|e| e.to_str()).filter(|e| *e == "000" || *e == "001");
        let Some(start) = number.and_then(|e| e.parse::<u32>().ok()) else { return Ok(None) };
        let (mut pieces, mut len) = (Vec::new(), 0u64);
        for n in start..=999 {
            let path = first.with_extension(format!("{n:03}"));
            if !path.is_file() {
                break;
            }
            let piece = map(&path)?;
            let size = piece.len() as u64;
            pieces.push((len, piece));
            len += size;
        }
        Ok((pieces.len() > 1).then_some(Split { pieces, len }))
    }
}

impl ReadAt for Split {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let (mut pos, mut done) = (offset, 0usize);
        while done < buf.len() {
            // The last piece that starts at or before `pos`.
            let at = self.pieces.partition_point(|(start, _)| *start <= pos).saturating_sub(1);
            let (start, piece) = &self.pieces[at];
            let inside = usize::try_from(pos - start).ok().filter(|&i| i < piece.len());
            let Some(inside) = inside else {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the image"));
            };
            let n = (piece.len() - inside).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&piece[inside..inside + n]);
            done += n;
            pos += n as u64;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// Virtual machine disk formats, by signature. They are not read: the error names the format
/// and the conversion, which is better than "not an image".
fn virtual_disk(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"QFI\xfb") {
        Some("qcow2")
    } else if head.starts_with(b"KDMV") || head.starts_with(b"# Disk DescriptorFile") {
        Some("VMDK")
    } else if head.starts_with(b"vhdxfile") {
        Some("VHDX")
    } else if head.starts_with(b"<<< ") && head.windows(10).any(|w| w == b"Disk Image") {
        Some("VDI")
    } else if head.starts_with(b"conectix") {
        Some("VHD")
    } else {
        None
    }
}

/// Opens the filesystems inside one partition. A partition that holds no supported or
/// readable filesystem gives an empty list.
fn open_volumes(partition: Part) -> Vec<Opened> {
    fn boxed(volume: impl Volume + Send + 'static) -> Opened {
        Box::new(volume)
    }
    match partitions::filesystem_signature(&partition) {
        Some("ext4") => Ext4::open(partition).ok().map(boxed).into_iter().collect(),
        Some("xfs") => Xfs::open(partition).ok().map(boxed).into_iter().collect(),
        // One container holds several volumes; encrypted and sealed ones cannot be opened.
        Some("apfs") => Apfs::open(partition)
            .map(|container| {
                container.volumes().iter().filter_map(|v| container.volume(v.index).ok()).map(boxed).collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Lists `path` when it is a disk image; `Ok(None)` when it is not one (so the caller can try
/// archives). A file that starts like an archive is never an image. Body files go to `scratch`.
pub(crate) fn open(path: &Path, scratch: &Path) -> io::Result<Option<Listed>> {
    let mut head = [0u8; 512];
    let read = File::open(path)?.read(&mut head)?;
    let head = &head[..read];
    let archive = head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x05\x06")
        || head.starts_with(&[0x1f, 0x8b])
        || head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        || head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0])
        || head.starts_with(b"BZh")
        || head.get(257..262) == Some(b"ustar");
    if archive || head.is_empty() {
        return Ok(None);
    }
    if let Some(format) = virtual_disk(head) {
        return Err(io::Error::other(format!(
            "a {format} virtual disk is not read; convert it first: qemu-img convert -O raw <disk> disk.raw"
        )));
    }
    let mut segments = None;
    let reader: Shared = if ewf::signature(head).is_some() {
        Arc::new(ewf::Ewf::open(path)?)
    } else if let Some(split) = Split::open(path)? {
        segments = Some(format!("raw image read from {} segments, {} bytes in all", split.pieces.len(), split.len));
        Arc::new(split)
    } else {
        Arc::new(Mapped(map(path)?))
    };
    let parts = partitions::scan(&reader);
    if parts.is_empty() {
        // An EWF file is evidence the user meant as an image; a raw file is just not one.
        return if ewf::signature(head).is_some() {
            Err(io::Error::other("the image has no recognizable partition table or filesystem"))
        } else {
            Ok(None)
        };
    }
    let (entries, image, mut notes) = build(reader, parts, &open_volumes, scratch)?;
    notes.splice(0..0, segments);
    Ok(Some((entries, image, notes)))
}

/// Opens every partition's volumes, walks them and returns the entries, the open volumes and
/// the warnings.
fn build(
    reader: Shared,
    parts: Vec<Partition>,
    open: &dyn Fn(Part) -> Vec<Opened>,
    scratch: &Path,
) -> io::Result<Listed> {
    let mut entries = Vec::new();
    let mut volumes: Vec<Opened> = Vec::new();
    let mut skipped = Vec::new();
    let mut notes = Vec::new();
    let mut physical = Vec::new();
    let mut physical_names = Vec::new();
    for part in &parts {
        let slice = Slice { inner: reader.clone(), start: part.start, len: part.len };
        match part.unsupported {
            Some(partitions::LVM_REASON) => {
                physical.push((part.index, slice));
                physical_names.push(format!("p{} {}", part.index, part.type_name));
                continue;
            }
            Some(why) => {
                notes.push(format!("partition {} ({}) skipped: {why}", part.index, part.type_name));
                skipped.push(format!("p{} {} ({why})", part.index, part.type_name));
                continue;
            }
            None => {}
        }
        let opened = open(slice);
        if opened.is_empty() {
            skipped.push(format!("p{} {} (no supported filesystem)", part.index, part.type_name));
        }
        add_volumes(&format!("p{}", part.index), opened, scratch, &mut entries, &mut volumes, &mut notes)?;
    }
    if !physical.is_empty() {
        let (logical, lvm_notes) = lvm::open(physical);
        notes.extend(lvm_notes);
        if logical.is_empty() {
            let why = format!("{}, no logical volume could be read", partitions::LVM_REASON);
            skipped.extend(physical_names.iter().map(|name| format!("{name} ({why})")));
        }
        for lv in logical {
            let opened = open(Slice { inner: lv.reader, start: 0, len: lv.len });
            if opened.is_empty() {
                skipped.push(format!("{} (no supported filesystem)", lv.name));
            }
            add_volumes(&lv.name, opened, scratch, &mut entries, &mut volumes, &mut notes)?;
        }
    }
    if volumes.is_empty() {
        return Err(io::Error::other(format!("no readable filesystem in the image: {}", skipped.join(", "))));
    }
    Ok((entries, Image { volumes }, notes))
}

/// Lists the volumes found on one partition or logical volume, named `base` (`base` + `v<n>`
/// when there are several), and adds their entries, notes and body files.
fn add_volumes(
    base: &str,
    opened: Vec<Opened>,
    scratch: &Path,
    entries: &mut Vec<Entry>,
    volumes: &mut Vec<Opened>,
    notes: &mut Vec<String>,
) -> io::Result<()> {
    let several = opened.len() > 1;
    for (nth, volume) in opened.into_iter().enumerate() {
        let name = if several { format!("{base}v{}", nth + 1) } else { base.to_string() };
        std::fs::create_dir_all(scratch)?;
        let body_path = scratch.join(format!("bodyfile-{name}.txt"));
        let mut listing = Listing {
            name: &name,
            volume: volumes.len(),
            entries: Vec::new(),
            body: BufWriter::new(File::create(&body_path)?),
            lines: 0,
            error: None,
        };
        let (mut kept, mut more) = (Vec::new(), 0usize);
        let walked = volume.walk(&mut |node| listing.add(node), &mut |warning| {
            if kept.len() < WARNINGS_KEPT {
                kept.push(warning);
            } else {
                more += 1;
            }
        });
        if let Err(e) = walked {
            kept.push(format!("listing stopped early: {e}"));
        }
        notes.extend(kept.into_iter().map(|w| format!("{name} ({}): {w}", volume.kind())));
        if more > 0 {
            notes.push(format!("{name}: {more} more warnings"));
        }
        let Listing { entries: found, body, lines, error, .. } = listing;
        if let Some(e) = error {
            return Err(e);
        }
        body.into_inner().map_err(io::IntoInnerError::into_error)?;
        if lines == 0 {
            let _ = std::fs::remove_file(&body_path);
        } else {
            let size = std::fs::metadata(&body_path)?.len();
            entries.push(Entry {
                path: format!("{name}/bodyfile/bodyfile.txt"),
                size,
                mtime: 0,
                mode: 0o644,
                uid: 0,
                gid: 0,
                link: None,
                store: Store::File(body_path),
            });
        }
        entries.extend(found);
        volumes.push(volume);
    }
    Ok(())
}

/// The entries and body file of one volume, filled as the walk visits nodes.
struct Listing<'n> {
    name: &'n str,
    /// Index of this volume in `Image::volumes`.
    volume: usize,
    entries: Vec<Entry>,
    body: BufWriter<File>,
    lines: u64,
    /// The first error writing the body file.
    error: Option<io::Error>,
}

impl Listing<'_> {
    fn add(&mut self, node: Node) {
        // A path that climbs out of the volume must not become an entry.
        if node.path.split('/').any(|segment| segment == "..") {
            return;
        }
        if self.error.is_none() {
            self.error = self.body_line(&node).err();
        }
        let path = node.path.trim_matches('/');
        if path.is_empty() {
            return;
        }
        let store = match node.kind {
            Kind::File => Store::Volume { volume: self.volume, inode: node.inode, allocated: node.allocated },
            Kind::Symlink if node.link_target.is_some() => Store::Dropped,
            _ => return, // directories are implied by paths; devices and sockets are never read
        };
        let is_link = node.kind == Kind::Symlink;
        self.entries.push(Entry {
            path: format!("{}/[root]/{path}", self.name),
            size: if is_link { 0 } else { node.size },
            mtime: node.modified.map_or(0, secs),
            mode: node.mode,
            uid: node.uid,
            gid: node.gid,
            link: node.link_target.filter(|_| is_link),
            store,
        });
    }

    /// One Sleuth Kit 3.x body file line: `MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`.
    fn body_line(&mut self, node: &Node) -> io::Result<()> {
        // Names are written as they are (the parser cuts the fixed fields from the right, so
        // `|` is safe); only line breaks would split a record.
        let name: String = node.path.chars().map(|c| if c == '\n' || c == '\r' { '?' } else { c }).collect();
        let mode = mode_string(typed_mode(node));
        let time = |t: Option<i64>| t.map_or(0, secs);
        write!(self.body, "0|/{name}")?;
        if let (Kind::Symlink, Some(target)) = (node.kind, &node.link_target) {
            let target: String = target.chars().map(|c| if c == '\n' || c == '\r' { '?' } else { c }).collect();
            write!(self.body, " -> {target}")?;
        }
        self.lines += 1;
        writeln!(
            self.body,
            "|{}|{mode}|{}|{}|{}|{}|{}|{}|{}",
            node.inode,
            node.uid,
            node.gid,
            node.size,
            time(node.accessed),
            time(node.modified),
            time(node.changed),
            time(node.created),
        )
    }
}

/// Nanoseconds since the epoch to seconds, rounding toward negative infinity.
fn secs(nanos: i64) -> i64 {
    nanos.div_euclid(1_000_000_000)
}

/// The mode with a file type, taking it from `kind` when the filesystem left the type bits out.
fn typed_mode(node: &Node) -> u32 {
    if node.mode & 0o170000 != 0 {
        return node.mode;
    }
    node.mode
        | match node.kind {
            Kind::File => 0o100000,
            Kind::Directory => 0o040000,
            Kind::Symlink => 0o120000,
            Kind::Other => 0,
        }
}

/// `ls -l` style: type character, then `rwx` triples with setuid, setgid and sticky shown as
/// `s`/`S` and `t`/`T`.
pub(crate) fn mode_string(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    for (shift, special, on, off) in [(6, 0o4000, 's', 'S'), (3, 0o2000, 's', 'S'), (0, 0o1000, 't', 'T')] {
        let bits = mode >> shift & 7;
        out.push(if bits & 4 != 0 { 'r' } else { '-' });
        out.push(if bits & 2 != 0 { 'w' } else { '-' });
        out.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => on,
            (false, true) => off,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

impl Source {
    /// A source over an image reader with an injected volume opener, for tests.
    #[cfg(test)]
    pub(crate) fn from_image(path: &Path, reader: Shared, open: &dyn Fn(Part) -> Vec<Opened>) -> io::Result<Source> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SOURCES: AtomicUsize = AtomicUsize::new(0);
        let n = SOURCES.fetch_add(1, Ordering::Relaxed);
        let scratch = std::env::temp_dir().join(format!("nixcavate-image-test-{}-{n}", std::process::id()));
        let parts = partitions::scan(&reader);
        let (entries, image, mut warnings) = build(reader, parts, open, &scratch)?;
        let mut source = Source::from_entries(path, entries, None);
        source.image = Some(image);
        warnings.append(&mut source.warnings);
        source.warnings = warnings;
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use super::partitions::testing::Sparse;
    use super::*;
    use crate::{discover, Os, Pattern};

    /// An in-memory filesystem: a list of nodes and the content of the regular files.
    struct Fake {
        nodes: Vec<(Node, Vec<u8>)>,
    }

    fn node(path: &str, inode: u64, kind: Kind, mode: u32, size: u64) -> Node {
        Node {
            path: path.into(),
            inode,
            kind,
            mode,
            uid: 1000,
            gid: 100,
            size,
            allocated: size,
            links: 1,
            accessed: Some(1_700_000_003_000_000_000),
            modified: Some(1_700_000_002_999_999_999),
            changed: Some(1_700_000_001_000_000_000),
            created: None,
            link_target: None,
        }
    }

    impl Fake {
        fn linux(hostname: &str) -> Fake {
            let file = |path: &str, inode, content: &[u8]| {
                (node(path, inode, Kind::File, 0o100644, content.len() as u64), content.to_vec())
            };
            let dir = |path: &str, inode| (node(path, inode, Kind::Directory, 0o040755, 4096), Vec::new());
            let mut link = node("etc/os-release", 14, Kind::Symlink, 0o120777, 21);
            link.link_target = Some("../usr/lib/os-release".into());
            Fake {
                nodes: vec![
                    dir("", 2),
                    dir("etc", 11),
                    file("etc/hostname", 12, format!("{hostname}\n").as_bytes()),
                    file("etc/passwd", 13, b"root:x:0:0::/root:/bin/sh\n"),
                    (link, Vec::new()),
                    dir("usr", 20),
                    dir("usr/lib", 21),
                    file("usr/lib/os-release", 22, b"PRETTY_NAME=\"Test Linux 1\"\n"),
                    file("var/log/auth.log", 30, b"line\n"),
                    (node("dev/null", 31, Kind::Other, 0o020666, 0), Vec::new()),
                    (node("bad/../../escape", 32, Kind::File, 0o100644, 1), vec![0]),
                    file("odd\nname|x", 33, b"x"),
                ],
            }
        }
    }

    impl Volume for Fake {
        fn kind(&self) -> &'static str {
            "fake"
        }

        fn walk(&self, visit: &mut dyn FnMut(Node), _warn: &mut dyn FnMut(String)) -> nixcavate_fs::Result<()> {
            self.nodes.iter().for_each(|(n, _)| visit(n.clone()));
            Ok(())
        }

        fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> nixcavate_fs::Result<usize> {
            let (_, data) = self
                .nodes
                .iter()
                .find(|(n, _)| n.inode == inode)
                .ok_or_else(|| nixcavate_fs::Error::corrupt("inode"))?;
            let from = (offset as usize).min(data.len());
            let n = buf.len().min(data.len() - from);
            buf[..n].copy_from_slice(&data[from..from + n]);
            Ok(n)
        }
    }

    const MIB: u64 = 1 << 20;

    /// The GPT fixture with a Linux host on each partition whose size is in `sizes`.
    fn gpt_source(hosts: &'static [(u64, &'static str)]) -> Source {
        let open = move |partition: Part| {
            hosts
                .iter()
                .filter(|(size, _)| *size == partition.size())
                .map(|(_, name)| Box::new(Fake::linux(name)) as Opened)
                .collect()
        };
        Source::from_image(Path::new("disk.E01"), Arc::new(Sparse::load("gpt512.parts")), &open).unwrap()
    }

    #[test]
    fn single_volume_lists_discovers_and_reads() {
        // Partition 2 (16 MiB) is the only one with a filesystem.
        let source = gpt_source(&[(16 * MIB, "web01")]);
        let paths: Vec<&str> = source.entries().iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "p2/[root]/etc/hostname",
                "p2/[root]/etc/os-release",
                "p2/[root]/etc/passwd",
                "p2/[root]/odd\nname|x",
                "p2/[root]/usr/lib/os-release",
                "p2/[root]/var/log/auth.log",
                "p2/bodyfile/bodyfile.txt",
            ]
        );

        let entry = source.entry("p2/[root]/etc/passwd").unwrap();
        assert_eq!((entry.size, entry.mode, entry.uid, entry.gid), (26, 0o100644, 1000, 100));
        assert_eq!(entry.mtime, 1_700_000_002); // 2999999999 ns rounds down
        assert_eq!(&*source.read(entry).unwrap(), b"root:x:0:0::/root:/bin/sh\n");
        let link = source.entry("p2/[root]/etc/os-release").unwrap();
        assert_eq!((link.link.as_deref(), link.size), (Some("../usr/lib/os-release"), 0));

        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!((host.name.as_str(), host.os, host.root.as_str()), ("web01", Os::Linux, "p2/[root]"));
        assert_eq!(host.os_version, "Test Linux 1");
        assert_eq!(host.read_text("etc/os-release").as_deref(), Some("PRETTY_NAME=\"Test Linux 1\"\n"));

        // The bodyfile artifact's pattern is relative to the parent of the host root.
        let pattern = Pattern::new("../bodyfile/bodyfile.txt");
        let found: Vec<&crate::Entry> = host.find(&pattern).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(host.rel(found[0]), "../bodyfile/bodyfile.txt");
        let body = String::from_utf8(source.read(found[0]).unwrap().to_vec()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "0|/|2|drwxr-xr-x|1000|100|4096|1700000003|1700000002|1700000001|0");
        assert!(lines.contains(&"0|/etc/passwd|13|-rw-r--r--|1000|100|26|1700000003|1700000002|1700000001|0"));
        assert!(lines.contains(
            &"0|/etc/os-release -> ../usr/lib/os-release|14|lrwxrwxrwx|1000|100|21|1700000003|1700000002|1700000001|0"
        ));
        assert!(lines.contains(&"0|/dev/null|31|crw-rw-rw-|1000|100|0|1700000003|1700000002|1700000001|0"));
        assert!(lines.iter().any(|l| l.starts_with("0|/odd?name|x|33|")));
        assert!(!body.contains("escape"), "paths that leave the volume are dropped");
        assert_eq!(lines.len(), 11);
    }

    #[test]
    fn several_volumes_are_several_hosts_each_with_its_own_bodyfile() {
        let source = gpt_source(&[(16 * MIB, "alpha"), (8 * MIB, "beta")]);
        // 8 MiB matches partitions 1, 3 and 4 (efi, lvm, apfs); the LVM one has no signature
        // in this fixture, so all three open the fake.
        let hosts = discover(&source, None);
        let names: Vec<&str> = hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["beta", "alpha", "beta", "beta"]);
        let roots: Vec<&str> = hosts.iter().map(|h| h.root.as_str()).collect();
        assert_eq!(roots, ["p1/[root]", "p2/[root]", "p3/[root]", "p4/[root]"]);
        let pattern = Pattern::new("../bodyfile/bodyfile.txt");
        for host in &hosts {
            let found: Vec<String> = host.find(&pattern).map(|e| e.path.clone()).collect();
            assert_eq!(found, [format!("{}/bodyfile/bodyfile.txt", host.root.trim_end_matches("/[root]"))]);
        }
        // Reads come from the right volume.
        let hostname =
            |root: &str| source.read(source.entry(&format!("{root}/etc/hostname")).unwrap()).unwrap().to_vec();
        assert_eq!(hostname("p2/[root]"), b"alpha\n");
        assert_eq!(hostname("p3/[root]"), b"beta\n");
    }

    #[test]
    fn a_partition_with_several_volumes_gets_numbered_names() {
        let open = |_: Part| vec![Box::new(Fake::linux("one")) as Opened, Box::new(Fake::linux("two"))];
        let mut ext = vec![0u8; 4096];
        ext[1080..1082].copy_from_slice(&[0x53, 0xef]);
        let source =
            Source::from_image(Path::new("a.dd"), Arc::new(Bytes(Box::leak(ext.into_boxed_slice()))), &open).unwrap();
        assert!(source.entry("p1v1/[root]/etc/hostname").is_some());
        let second = source.entry("p1v2/[root]/etc/hostname").unwrap();
        assert_eq!(&*source.read(second).unwrap(), b"two\n");
    }

    #[test]
    fn no_readable_filesystem_is_an_error() {
        let err = Source::from_image(Path::new("x.dd"), Arc::new(Sparse::load("gpt512.parts")), &|_| Vec::new())
            .err()
            .unwrap();
        assert!(err.to_string().contains("no readable filesystem"), "{err}");
        assert!(err.to_string().contains("p5 swap"), "{err}");
    }

    #[test]
    fn unsupported_partitions_are_skipped_and_named() {
        let mut image = Sparse::load("gpt512.parts");
        image.pieces.push((18432 * 512, b"LUKS\xba\xbe\x00\x02".to_vec()));
        let open = |p: Part| {
            assert_ne!(p.size(), 16 * MIB, "the LUKS partition must not be opened");
            if p.size() == 8 * MIB {
                vec![Box::new(Fake::linux("h")) as Opened]
            } else {
                Vec::new()
            }
        };
        let source = Source::from_image(Path::new("x.dd"), Arc::new(image), &open).unwrap();
        assert!(source.entry("p1/[root]/etc/passwd").is_some());
        assert!(source.entry("p2/[root]/etc/passwd").is_none());
    }

    /// A GPT image whose partition 3 is an LVM physical volume holding the linear volume
    /// `vg0/root` of four extents (16 KiB).
    fn lvm_image() -> Sparse {
        use lvm::testing::*;
        let text = metadata("vg0", 1, &[uuid('A')], &lv("root", &segment(1, 0, 4, 0, 1)));
        let mut image = Sparse::load("gpt512.parts");
        image.pieces.push((51200 * 512, pv_image(&uuid('A'), &text, 512, 8, 0)));
        image
    }

    #[test]
    fn a_logical_volume_is_listed_like_a_partition_and_named_after_itself() {
        let open = |p: Part| {
            if p.size() != 4 * 4096 {
                return Vec::new();
            }
            // The first extent of the volume is the second extent of the physical volume.
            let mut head = [0u8; 8];
            p.read_at(0, &mut head).unwrap();
            let at = (lvm::testing::DATA_AT + 4096) as usize;
            let expected: Vec<u8> = (0..8).map(|i| lvm::testing::pattern((at + i) as u64, 0)).collect();
            assert_eq!(head.to_vec(), expected);
            vec![Box::new(Fake::linux("lvmhost")) as Opened]
        };
        let source = Source::from_image(Path::new("disk.raw"), Arc::new(lvm_image()), &open).unwrap();
        let passwd = source.entry("vg0-root/[root]/etc/passwd").unwrap();
        assert_eq!(&*source.read(passwd).unwrap(), b"root:x:0:0::/root:/bin/sh\n");
        assert!(source.entry("vg0-root/bodyfile/bodyfile.txt").is_some());
        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1);
        assert_eq!((hosts[0].name.as_str(), hosts[0].root.as_str()), ("lvmhost", "vg0-root/[root]"));
    }

    #[test]
    fn a_physical_volume_without_readable_logical_volumes_is_named_in_the_error() {
        let mut lvm = vec![0u8; 1 << 20];
        lvm[512..520].copy_from_slice(b"LABELONE");
        lvm[512 + 24..512 + 32].copy_from_slice(b"LVM2 001");
        let reader = Arc::new(Bytes(Box::leak(lvm.into_boxed_slice())));
        let err = Source::from_image(Path::new("x.dd"), reader, &|_| Vec::new()).err().unwrap();
        assert!(err.to_string().contains("no readable filesystem"), "{err}");
        assert!(err.to_string().contains("LVM2 physical volume"), "{err}");
    }

    #[test]
    fn a_logical_volume_with_no_filesystem_is_skipped_quietly() {
        let err = Source::from_image(Path::new("x.dd"), Arc::new(lvm_image()), &|_| Vec::new()).err().unwrap();
        assert!(err.to_string().contains("vg0-root (no supported filesystem)"), "{err}");
    }

    /// A real E01 of a GPT disk, through the EWF reader, the partition scan and the listing.
    #[test]
    fn e01_with_a_gpt_disk_end_to_end() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/gpt-disk.E01");
        let reader = ewf::Ewf::open(&path).unwrap();
        let open = |partition: Part| {
            let name = partitions::filesystem_signature(&partition).unwrap_or("none");
            if name == "none" {
                Vec::new()
            } else {
                vec![Box::new(Fake::linux(name)) as Opened]
            }
        };
        let source = Source::from_image(&path, Arc::new(reader), &open).unwrap();
        let hosts = discover(&source, None);
        let names: Vec<&str> = hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["ext4", "xfs"]);
        assert_eq!(hosts[1].root, "p2/[root]");
    }

    /// `test_files/image/lvm/build.sh` made this disk with the real LVM tools: two physical
    /// volumes, and a logical volume whose first segment is on the second of them. `big.txt`
    /// crosses the segment boundary, so reading it whole proves the mapping.
    #[test]
    fn a_real_lvm_disk_is_read_through_its_segments() {
        let dir = std::env::temp_dir().join(format!("nixcavate-image-lvm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/lvm/disk.img.zst");
        let disk = dir.join("disk.img");
        std::fs::write(&disk, zstd::decode_all(File::open(fixture).unwrap()).unwrap()).unwrap();

        let source = Source::open(&disk, &|_| true, &dir.join("scratch")).unwrap();
        assert!(source.warnings.is_empty(), "{:?}", source.warnings);
        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1, "the swap volume holds no filesystem");
        assert_eq!((hosts[0].name.as_str(), hosts[0].root.as_str()), ("lvmhost", "vg0-root/[root]"));
        let big = source.read(source.entry("vg0-root/[root]/big.txt").unwrap()).unwrap();
        let expected: String =
            (0..60000).map(|i| format!("{i:07} the quick brown fox jumps over the lazy dog\n")).collect();
        assert!(big.len() == 3_120_000 && &*big == expected.as_bytes(), "{} bytes", big.len());
        drop(source);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Imaging tools split a raw image into `.001`, `.002`...: the pieces are one disk.
    #[test]
    fn a_split_raw_image_is_read_as_one_disk() {
        let dir = std::env::temp_dir().join(format!("nixcavate-image-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/host/disk.img.zst");
        let disk = zstd::decode_all(File::open(fixture).unwrap()).unwrap();
        std::fs::write(dir.join("whole.img"), &disk).unwrap();
        // Uneven pieces, so no piece boundary falls on a block boundary.
        for (n, piece) in disk.chunks(3_000_001).enumerate() {
            std::fs::write(dir.join(format!("disk.{:03}", n + 1)), piece).unwrap();
        }
        let listing = |name: &str| {
            let source = Source::open(&dir.join(name), &|_| true, &dir.join(name).with_extension("scratch")).unwrap();
            let files: Vec<(String, Vec<u8>)> = source
                .entries()
                .iter()
                .filter(|e| !e.path.contains("bodyfile") && e.link.is_none() && e.mode & 0o170_000 == 0o100_000)
                .map(|e| (e.path.clone(), source.read(e).unwrap().to_vec()))
                .collect();
            (files, source.warnings.clone())
        };
        let (whole, _) = listing("whole.img");
        let (split, warnings) = listing("disk.001");
        assert!(whole.len() >= 5 && whole == split);
        assert!(warnings.iter().any(|w| w.contains("3 segments")), "{warnings:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Virtual machine disk formats are named, with the way out, instead of "not an image".
    #[test]
    fn virtual_disk_formats_are_named() {
        let dir = std::env::temp_dir().join(format!("nixcavate-image-vm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let heads: [(&str, &[u8]); 6] = [
            ("qcow2", b"QFI\xfb\0\0\0\x03"),
            ("VMDK", b"KDMV\x01\0\0\0"),
            ("VMDK", b"# Disk DescriptorFile\nversion=1\n"),
            ("VHDX", b"vhdxfile\0\0"),
            ("VDI", b"<<< Oracle VM VirtualBox Disk Image >>>\n"),
            ("VHD", b"conectix\0\0\0\x02"),
        ];
        for (name, head) in heads {
            let mut data = head.to_vec();
            data.resize(4096, 0);
            std::fs::write(dir.join("disk"), &data).unwrap();
            let err = Source::open(&dir.join("disk"), &|_| true, &dir).err().unwrap().to_string();
            assert!(err.contains(name) && err.contains("qemu-img convert -O raw"), "{name}: {err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_open_recognizes_images_and_leaves_other_files_alone() {
        let dir = std::env::temp_dir().join(format!("nixcavate-image-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keep = |_: &str| true;

        // An E01 with no partition table or filesystem: claimed as an image, with a clear error.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/best.E01");
        let err = Source::open(&fixture, &keep, &dir).err().unwrap();
        assert!(err.to_string().contains("no recognizable partition table"), "{err}");

        // A raw ext4-looking image: claimed, but nothing can open it until the readers are plugged in.
        let mut ext = vec![0u8; 8192];
        ext[1080..1082].copy_from_slice(&[0x53, 0xef]);
        std::fs::write(dir.join("a.img"), &ext).unwrap();
        let err = Source::open(&dir.join("a.img"), &keep, &dir).err().unwrap();
        assert!(err.to_string().contains("no readable filesystem"), "{err}");

        // Not an image, not an archive: the archive error is unchanged.
        std::fs::write(dir.join("notes.txt"), b"hello there, this is text").unwrap();
        let err = Source::open(&dir.join("notes.txt"), &keep, &dir).err().unwrap();
        assert!(err.to_string().contains("not a directory, disk image, tar or zip archive"), "{err}");

        // A compressed disk image is not a tar: the error says what to do.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &ext).unwrap();
        std::fs::write(dir.join("a.img.gz"), gz.finish().unwrap()).unwrap();
        let err = Source::open(&dir.join("a.img.gz"), &keep, &dir).err().unwrap();
        assert!(err.to_string().contains("decompress a compressed disk image first"), "{err}");

        // A zip that happens to hold 0xEF53 where an ext magic would be is still a zip.
        let mut zip = b"PK\x05\x06".to_vec();
        zip.resize(8192, 0);
        zip[1080..1082].copy_from_slice(&[0x53, 0xef]);
        std::fs::write(dir.join("z.zip"), &zip).unwrap();
        assert!(!matches!(open(&dir.join("z.zip"), &dir), Ok(Some(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A volume that lists `etc/passwd` twice and warns `warnings` times.
    struct Noisy {
        warnings: usize,
    }

    impl Volume for Noisy {
        fn kind(&self) -> &'static str {
            "noisy"
        }

        fn walk(&self, visit: &mut dyn FnMut(Node), warn: &mut dyn FnMut(String)) -> nixcavate_fs::Result<()> {
            visit(node("etc/passwd", 13, Kind::File, 0o100644, 5));
            visit(node("etc/passwd", 14, Kind::File, 0o100644, 6));
            (0..self.warnings).for_each(|i| warn(format!("warning {i}")));
            Ok(())
        }

        fn read(&self, inode: u64, _offset: u64, buf: &mut [u8]) -> nixcavate_fs::Result<usize> {
            let data: &[u8] = if inode == 13 { b"first" } else { b"second" };
            buf[..data.len()].copy_from_slice(data);
            Ok(data.len())
        }
    }

    fn noisy_source(warnings: usize) -> Source {
        let open = move |p: Part| {
            if p.size() == 16 * MIB {
                vec![Box::new(Noisy { warnings }) as Opened]
            } else {
                Vec::new()
            }
        };
        Source::from_image(Path::new("disk.E01"), Arc::new(Sparse::load("gpt512.parts")), &open).unwrap()
    }

    #[test]
    fn warnings_are_kept_per_volume_up_to_a_cap() {
        let source = noisy_source(1000);
        let mine: Vec<&String> =
            source.warnings.iter().filter(|w| w.starts_with("p2 (") || w.starts_with("p2:")).collect();
        assert_eq!(mine.len(), 21, "20 warnings and a count of the rest");
        assert!(mine.iter().any(|w| w.contains("980 more warnings")), "{mine:?}");
    }

    #[test]
    fn a_duplicate_path_keeps_the_first_entry_and_warns() {
        let source = noisy_source(0);
        let entry = source.entry("p2/[root]/etc/passwd").unwrap();
        assert_eq!(&*source.read(entry).unwrap(), b"first");
        assert!(source.warnings.iter().any(|w| w.contains("p2/[root]/etc/passwd")), "{:?}", source.warnings);
    }

    #[test]
    fn the_body_file_is_written_to_scratch_not_kept_in_memory() {
        let source = gpt_source(&[(16 * MIB, "web01")]);
        let entry = source.entry("p2/bodyfile/bodyfile.txt").unwrap();
        assert!(matches!(entry.store, Store::File(_)), "{:?}", entry.store);
        assert!(String::from_utf8_lossy(&source.read(entry).unwrap()).contains("|/etc/passwd|13|"));
    }

    fn fixture_fs(rel: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/fs").join(rel);
        zstd::decode_all(&std::fs::read(path).unwrap()[..]).unwrap()
    }

    fn le32(d: &[u8], at: usize) -> usize {
        u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
    }

    #[test]
    fn apfs_volumes_after_an_empty_slot_are_opened() {
        fn fletcher64(data: &[u8]) -> u64 {
            let (mut s1, mut s2) = (0u64, 0u64);
            for w in data.chunks_exact(4) {
                s1 = (s1 + u64::from(u32::from_le_bytes(w.try_into().unwrap()))) % 0xffff_ffff;
                s2 = (s2 + s1) % 0xffff_ffff;
            }
            let c1 = 0xffff_ffff - (s1 + s2) % 0xffff_ffff;
            ((0xffff_ffff - (s1 + c1) % 0xffff_ffff) << 32) | c1
        }
        let disk = fixture_fs("apfs/basic.dmg.zst");
        let part = partitions::scan(&Bytes(&disk)).into_iter().find(|p| p.type_name == "apple_apfs").unwrap();
        let mut container = disk[part.start as usize..(part.start + part.len) as usize].to_vec();
        // Move the only volume from slot 0 to slot 1 in every valid container superblock.
        let mut moved = 0;
        for block in container.chunks_mut(4096) {
            let sum = u64::from_le_bytes(block[..8].try_into().unwrap());
            if &block[32..36] != b"NXSB" || sum != fletcher64(&block[8..]) {
                continue;
            }
            block[180..184].copy_from_slice(&2u32.to_le_bytes());
            block.copy_within(184..192, 192);
            block[184..192].fill(0);
            let sum = fletcher64(&block[8..]);
            block[..8].copy_from_slice(&sum.to_le_bytes());
            moved += 1;
        }
        assert!(moved > 0);
        let len = container.len() as u64;
        let container: Shared = Arc::new(Bytes(Box::leak(container.into_boxed_slice())));
        assert_eq!(open_volumes(Slice { inner: container, start: 0, len }).len(), 1);
    }

    /// ext4.img with `small.txt` (inode 19) claiming `size` bytes; it holds one 4 KiB block.
    fn ext4_with_small_txt_size(size: u32) -> Vec<u8> {
        let mut data = fixture_fs("ext4/ext4.img.zst");
        let table = le32(&data, 4096 + 8) * 4096;
        data[table + 18 * 256 + 4..table + 18 * 256 + 8].copy_from_slice(&size.to_le_bytes());
        data
    }

    #[test]
    fn a_huge_mostly_unallocated_file_is_not_materialized() {
        let data = ext4_with_small_txt_size(200 << 20);
        let reader = Arc::new(Bytes(Box::leak(data.into_boxed_slice())));
        let source = Source::from_image(Path::new("x.img"), reader, &open_volumes).unwrap();
        let entry = source.entry("p1/[root]/small.txt").unwrap();
        assert_eq!(entry.size, 200 << 20);
        assert!(source.read(entry).is_err(), "200 MiB read for a file of one block");
        let medium = source.entry("p1/[root]/medium.txt").unwrap();
        assert_eq!(source.read(medium).unwrap().len() as u64, medium.size);
    }

    /// Counts reads of the ext4 superblock, which only opening a volume does.
    struct Opens {
        image: &'static [u8],
        superblock_reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ReadAt for Opens {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            if offset == 1024 && buf.len() == 1024 {
                self.superblock_reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Bytes(self.image).read_at(offset, buf)
        }

        fn size(&self) -> u64 {
            self.image.len() as u64
        }
    }

    #[test]
    fn reads_do_not_reopen_the_volume() {
        let image: &'static [u8] = Box::leak(fixture_fs("ext4/ext4.img.zst").into_boxed_slice());
        let opens = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = Arc::new(Opens { image, superblock_reads: opens.clone() });
        let source = Source::from_image(Path::new("x.img"), reader, &open_volumes).unwrap();
        let after_listing = opens.load(std::sync::atomic::Ordering::Relaxed);
        let mut read = 0;
        for entry in source.entries().iter().filter(|e| matches!(e.store, Store::Volume { .. })).take(200) {
            source.read(entry).unwrap();
            read += 1;
        }
        assert!(read > 100);
        assert_eq!(opens.load(std::sync::atomic::Ordering::Relaxed), after_listing, "a read reopened the volume");
    }

    #[test]
    fn mode_strings() {
        assert_eq!(mode_string(0o100644), "-rw-r--r--");
        assert_eq!(mode_string(0o104755), "-rwsr-xr-x");
        assert_eq!(mode_string(0o104644), "-rwSr--r--");
        assert_eq!(mode_string(0o102755), "-rwxr-sr-x");
        assert_eq!(mode_string(0o101777), "-rwxrwxrwt");
        assert_eq!(mode_string(0o041777), "drwxrwxrwt");
        assert_eq!(mode_string(0o041666), "drw-rw-rwT");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
        assert_eq!(mode_string(0o020660), "crw-rw----");
        assert_eq!(mode_string(0o060660), "brw-rw----");
        assert_eq!(mode_string(0o010600), "prw-------");
        assert_eq!(mode_string(0o140755), "srwxr-xr-x");
        assert_eq!(mode_string(0o644), "-rw-r--r--");
    }
}

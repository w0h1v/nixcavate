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
//! uses `p<index>v<n>`.
//!
//! # Ownership and memory
//!
//! The volumes own a shared handle on the image reader, so the [`Image`] keeps every volume
//! open for the whole run and a file read goes straight to its volume. Listing keeps one
//! [`Entry`] per file and link; body files are written to the scratch directory, and each
//! volume keeps its first [`WARNINGS_KEPT`] warnings plus a count of the rest.

mod ewf;
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
    let reader: Shared =
        if ewf::signature(head).is_some() { Arc::new(ewf::Ewf::open(path)?) } else { Arc::new(Mapped(map(path)?)) };
    let parts = partitions::scan(&reader);
    if parts.is_empty() {
        // An EWF file is evidence the user meant as an image; a raw file is just not one.
        return if ewf::signature(head).is_some() {
            Err(io::Error::other("the image has no recognizable partition table or filesystem"))
        } else {
            Ok(None)
        };
    }
    build(reader, parts, &open_volumes, scratch).map(Some)
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
    for part in &parts {
        if let Some(why) = part.unsupported {
            notes.push(format!("partition {} ({}) skipped: {why}", part.index, part.type_name));
            skipped.push(format!("p{} {} ({why})", part.index, part.type_name));
            continue;
        }
        let opened = open(Slice { inner: reader.clone(), start: part.start, len: part.len });
        if opened.is_empty() {
            skipped.push(format!("p{} {} (no supported filesystem)", part.index, part.type_name));
        }
        let several = opened.len() > 1;
        for (nth, volume) in opened.into_iter().enumerate() {
            let name = if several { format!("p{}v{}", part.index, nth + 1) } else { format!("p{}", part.index) };
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
    }
    if volumes.is_empty() {
        return Err(io::Error::other(format!("no readable filesystem in the image: {}", skipped.join(", "))));
    }
    Ok((entries, Image { volumes }, notes))
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

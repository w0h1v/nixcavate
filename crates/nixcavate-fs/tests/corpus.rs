//! Dumps one ext4, XFS, Btrfs or UFS volume of an external image, for comparison with what a real
//! mount shows. Ignored by default: it needs an image that is not in the repository. A Btrfs
//! volume is dumped as the tree its system mounts (root subvolume plus `/etc/fstab` mounts),
//! with zlib and zstd extents decompressed by `flate2` and `zstd`.
//!
//! ```sh
//! FS_IMAGE=disk.raw FS_OFFSET=134217728 FS_SIZE=3085959168 FS_DUMP=out.tsv \
//!     cargo test --release -p nixcavate-fs --test corpus -- --ignored
//! ```
//!
//! A ZFS pool with several members in the image takes them all as `FS_MEMBERS=offset:size,...`
//! instead of `FS_OFFSET` and `FS_SIZE`.
//!
//! One line per node, tab-separated, in the layout of
//! `find . -printf '%y\t%s\t%m\t%U\t%G\t%T@\t%p\t%l\n'` plus the SHA-256 of each regular
//! file's content (`-` when it was not read), then the inode number, link count and the access,
//! change and creation times in nanoseconds (0 when absent). Lines starting with `!` are walk
//! warnings and read errors.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::time::Instant;

use nixcavate_fs::btrfs::{self, Compression, Decompress};
use nixcavate_fs::{ext4, read_all, ufs, xfs, zfs, Kind, Node, ReadAt, Slice, Volume};
use sha2::{Digest, Sha256};

struct Disk(File, u64);

impl ReadAt for Disk {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(buf, offset)
    }

    fn size(&self) -> u64 {
        self.1
    }
}

struct Codecs;

impl Decompress for Codecs {
    fn decompress(&self, kind: Compression, input: &[u8], out: &mut Vec<u8>, limit: usize) -> nixcavate_fs::Result<()> {
        let reader: Box<dyn Read> = match kind {
            Compression::Zlib => Box::new(flate2::read::ZlibDecoder::new(input)),
            Compression::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(input)?.single_frame();
                decoder.window_log_max((usize::BITS - limit.saturating_sub(1).leading_zeros()).clamp(17, 24))?;
                Box::new(decoder)
            }
        };
        reader.take(limit as u64).read_to_end(out)?;
        Ok(())
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[test]
#[ignore = "needs an external image: see the file comment"]
fn dump_volume() {
    let path = var("FS_IMAGE").expect("FS_IMAGE");
    let file = File::open(&path).unwrap();
    let total = file.metadata().unwrap().len();
    let start: u64 = var("FS_OFFSET").map_or(0, |s| s.parse().unwrap());
    let len: u64 = var("FS_SIZE").map_or(total - start, |s| s.parse().unwrap());
    let part = Slice { inner: Disk(file.try_clone().unwrap(), total), start, len };
    let members: Vec<_> = var("FS_MEMBERS").map_or_else(
        || vec![Slice { inner: Disk(file.try_clone().unwrap(), total), start, len }],
        |list| {
            list.split(',')
                .map(|m| {
                    let (start, len) = m.split_once(':').unwrap();
                    let (start, len) = (start.parse().unwrap(), len.parse().unwrap());
                    Slice { inner: Disk(file.try_clone().unwrap(), total), start, len }
                })
                .collect()
        },
    );

    let volume: Box<dyn Volume + '_> = if zfs::probe(&members[0]) {
        Box::new(zfs::Zfs::open(members, Some(Box::new(Codecs))).unwrap())
    } else if ext4::probe(&part) {
        Box::new(ext4::Ext4::open(&part).unwrap())
    } else if xfs::probe(&part) {
        Box::new(xfs::Xfs::open(&part).unwrap())
    } else if btrfs::probe(&part) {
        Box::new(btrfs::Btrfs::open(&part, Some(Box::new(Codecs))).unwrap())
    } else if ufs::probe(&part) {
        Box::new(ufs::Ufs::open(&part).unwrap())
    } else {
        panic!("{path}: no ext4, XFS, Btrfs or UFS at offset {start}");
    };

    let mut nodes: Vec<Node> = Vec::new();
    let mut out = String::new();
    let started = Instant::now();
    volume.walk(&mut |n| nodes.push(n), &mut |w| writeln!(out, "!walk\t{w}").unwrap()).unwrap();
    let walked = started.elapsed();
    let (started, mut bytes) = (Instant::now(), 0u64);
    nodes.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    for n in &nodes {
        let kind = match n.kind {
            Kind::File => 'f',
            Kind::Directory => 'd',
            Kind::Symlink => 'l',
            Kind::Other => 'o',
        };
        let hash = match n.kind {
            Kind::File => match read_all(volume.as_ref(), n.inode, n.size, 1 << 30) {
                Ok(data) => {
                    bytes += data.len() as u64;
                    Sha256::digest(&data).iter().fold(String::new(), |mut s, b| {
                        write!(s, "{b:02x}").unwrap();
                        s
                    })
                }
                Err(e) => {
                    writeln!(out, "!read\t{}\t{e}", n.path).unwrap();
                    "-".into()
                }
            },
            _ => "-".into(),
        };
        writeln!(
            out,
            "{kind}\t{}\t{:o}\t{}\t{}\t{}\t{}\t{}\t{hash}\t{}\t{}\t{}\t{}\t{}",
            n.size,
            n.mode & 0o7777,
            n.uid,
            n.gid,
            n.modified.unwrap_or(0),
            n.path,
            n.link_target.as_deref().unwrap_or(""),
            n.inode,
            n.links,
            n.accessed.unwrap_or(0),
            n.changed.unwrap_or(0),
            n.created.unwrap_or(0),
        )
        .unwrap();
    }
    let read = started.elapsed();
    eprintln!(
        "{} nodes walked in {walked:?}; {bytes} bytes read and hashed in {read:?} ({:.0} MB/s)",
        nodes.len(),
        bytes as f64 / 1e6 / read.as_secs_f64()
    );
    std::fs::write(var("FS_DUMP").expect("FS_DUMP"), out).unwrap();
}

//! Dumps one ext4 or XFS volume of an external image, for comparison with what a real mount
//! shows. Ignored by default: it needs an image that is not in the repository.
//!
//! ```sh
//! FS_IMAGE=disk.raw FS_OFFSET=134217728 FS_SIZE=3085959168 FS_DUMP=out.tsv \
//!     cargo test --release -p nixcavate-fs --test corpus -- --ignored
//! ```
//!
//! One line per node, tab-separated, in the layout of
//! `find . -printf '%y\t%s\t%m\t%U\t%G\t%T@\t%p\t%l\n'` plus the SHA-256 of each regular
//! file's content (`-` when it was not read). Lines starting with `!` are walk warnings and
//! read errors.

use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use nixcavate_fs::{ext4, read_all, xfs, Kind, Node, ReadAt, Slice, Volume};
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
    let part = Slice { inner: Disk(file, total), start, len };

    let volume: Box<dyn Volume + '_> = if ext4::probe(&part) {
        Box::new(ext4::Ext4::open(&part).unwrap())
    } else if xfs::probe(&part) {
        Box::new(xfs::Xfs::open(&part).unwrap())
    } else {
        panic!("{path}: neither ext4 nor XFS at offset {start}");
    };

    let mut nodes: Vec<Node> = Vec::new();
    let mut out = String::new();
    volume.walk(&mut |n| nodes.push(n), &mut |w| writeln!(out, "!walk\t{w}").unwrap()).unwrap();
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
                Ok(data) => Sha256::digest(&data).iter().fold(String::new(), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                }),
                Err(e) => {
                    writeln!(out, "!read\t{}\t{e}", n.path).unwrap();
                    "-".into()
                }
            },
            _ => "-".into(),
        };
        writeln!(
            out,
            "{kind}\t{}\t{:o}\t{}\t{}\t{}\t{}\t{}\t{hash}",
            n.size,
            n.mode & 0o7777,
            n.uid,
            n.gid,
            n.modified.unwrap_or(0),
            n.path,
            n.link_target.as_deref().unwrap_or(""),
        )
        .unwrap();
    }
    std::fs::write(var("FS_DUMP").expect("FS_DUMP"), out).unwrap();
}

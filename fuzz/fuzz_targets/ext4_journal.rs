#![no_main]
//! The journals of two real images captured while mounted (ext3 without checksums, and ext4
//! with checksums and a log that wraps), damaged: opening replays them, then listing and
//! reading must return. The first input byte picks the image; the rest is a list of patches
//! written over its journal: a 4-byte offset into the journal, a 1-byte length, the bytes.
use std::io;
use std::sync::OnceLock;

use nixcavate_fs::{Kind, ReadAt, Volume};
use nixcavate_fuzz::fuzz_target;

/// An image, and where its journal is (byte offset and length).
struct Base {
    image: Vec<u8>,
    journal: usize,
    len: usize,
}

fn load(compressed: &[u8]) -> Base {
    let image = zstd::decode_all(compressed).expect("fixture");
    let bs = 1024usize << u32::from_le_bytes(image[1048..1052].try_into().unwrap());
    // The journal superblock: magic, block type 4. These images keep the journal in one extent.
    let sb = [0xC0, 0x3B, 0x39, 0x98, 0, 0, 0, 4];
    let block = (0..image.len() / bs).find(|&b| image[b * bs..b * bs + 8] == sb).expect("journal");
    let maxlen = u32::from_be_bytes(image[block * bs + 0x10..block * bs + 0x14].try_into().unwrap()) as usize;
    Base { journal: block * bs, len: (maxlen * bs).min(image.len() - block * bs), image }
}

fn bases() -> &'static [Base; 2] {
    static BASES: OnceLock<[Base; 2]> = OnceLock::new();
    BASES.get_or_init(|| {
        [
            load(include_bytes!("../../test_files/fs/ext4/journal-ext3.img.zst")),
            load(include_bytes!("../../test_files/fs/ext4/journal-wrap.img.zst")),
        ]
    })
}

/// The base image with patches over it, without copying it.
struct Patched<'a> {
    base: &'a [u8],
    patches: Vec<(usize, &'a [u8])>,
}

impl ReadAt for Patched<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::Error::other("offset"))?;
        let end = start.checked_add(buf.len()).filter(|&e| e <= self.base.len());
        let end = end.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"))?;
        buf.copy_from_slice(&self.base[start..end]);
        for &(at, bytes) in &self.patches {
            let (lo, hi) = (start.max(at), end.min(at + bytes.len()));
            if lo < hi {
                buf[lo - start..hi - start].copy_from_slice(&bytes[lo - at..hi - at]);
            }
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.base.len() as u64
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, mut rest)) = data.split_first() else { return };
    let base = &bases()[usize::from(pick & 1)];
    let mut patches = Vec::new();
    while rest.len() >= 5 {
        let at = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize % base.len;
        let n = usize::from(rest[4]).min(rest.len() - 5).min(base.len - at);
        patches.push((base.journal + at, &rest[5..5 + n]));
        rest = &rest[5 + n..];
    }
    let image = Patched { base: &base.image, patches };
    let Ok(volume) = nixcavate_fs::ext4::Ext4::open(&image) else { return };
    let mut files = Vec::new();
    let _ = volume.walk(&mut |node| files.push(node), &mut |_| {});
    let mut buf = [0u8; 4096];
    for node in files.iter().filter(|n| n.kind == Kind::File).take(16) {
        let _ = volume.read(node.inode, 0, &mut buf);
        let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
    }
});

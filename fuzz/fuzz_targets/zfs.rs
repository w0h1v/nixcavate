#![no_main]
use std::collections::BTreeMap;

use nixcavate_fs::{Kind, ReadAt, Volume};
use nixcavate_fuzz::fuzz_target;

/// A pool spreads its blocks over its whole device, so the input is a sparse device: runs of
/// a 4-byte little-endian sector number, a 2-byte sector count and that many 512-byte sectors,
/// over 256 MiB of zeros. A seed is a real pool's non-zero sectors in this form.
const SIZE: u64 = 256 << 20;

struct Sparse<'a>(BTreeMap<u64, &'a [u8]>);

impl<'a> Sparse<'a> {
    fn new(mut data: &'a [u8]) -> Sparse<'a> {
        let mut runs = BTreeMap::new();
        while data.len() >= 6 && runs.len() < 1 << 16 {
            let at = u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) * 512;
            let len = usize::from(u16::from_le_bytes([data[4], data[5]])) * 512;
            let body = &data[6..];
            let run = &body[..len.min(body.len())];
            runs.insert(at, run);
            data = &body[run.len()..];
        }
        Sparse(runs)
    }
}

impl ReadAt for Sparse<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= SIZE);
        let end = end.ok_or_else(|| std::io::Error::other("past the end"))?;
        buf.fill(0);
        // Runs that start before the end of the read; later runs win where they overlap.
        for (&at, run) in self.0.range(..end) {
            let run_end = at + run.len() as u64;
            if run_end <= offset {
                continue;
            }
            let (lo, hi) = (at.max(offset), run_end.min(end));
            buf[(lo - offset) as usize..(hi - offset) as usize].copy_from_slice(&run[(lo - at) as usize..(hi - at) as usize]);
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        SIZE
    }
}

// A hostile pool: opening, listing and reading must return, whatever the bytes are. No zlib
// or zstd decompressor is given (those are fuzzed upstream); LZ4, LZJB and ZLE are decoded by
// the reader.
fuzz_target!(|data: &[u8]| {
    let Ok(volume) = nixcavate_fs::zfs::Zfs::open(vec![Sparse::new(data)], None) else { return };
    let mut files = Vec::new();
    let _ = volume.walk(&mut |node| files.push(node), &mut |_| {});
    let mut buf = [0u8; 4096];
    for node in files.iter().filter(|n| matches!(n.kind, Kind::File | Kind::Symlink)).take(16) {
        let _ = volume.read(node.inode, 0, &mut buf);
        let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
    }
});

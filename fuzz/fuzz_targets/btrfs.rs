#![no_main]
use nixcavate_fs::{Bytes, Kind, Volume};
use nixcavate_fuzz::fuzz_target;

// A hostile image: opening, listing and reading must return, whatever the bytes are. No zlib
// or zstd decompressor is given (those are fuzzed upstream); LZO is decoded by the reader.
fuzz_target!(|data: &[u8]| {
    let image = Bytes(data);
    let Ok(volume) = nixcavate_fs::btrfs::Btrfs::open(&image, None) else { return };
    let mut files = Vec::new();
    let _ = volume.walk(&mut |node| files.push(node), &mut |_| {});
    let mut buf = [0u8; 4096];
    for node in files.iter().filter(|n| matches!(n.kind, Kind::File | Kind::Symlink)).take(16) {
        let _ = volume.read(node.inode, 0, &mut buf);
        let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
    }
});

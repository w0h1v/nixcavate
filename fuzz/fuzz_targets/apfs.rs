#![no_main]
use nixcavate_fs::{Bytes, Kind, Volume};
use nixcavate_fuzz::fuzz_target;

// A hostile image: opening, listing and reading must return, whatever the bytes are.
fuzz_target!(|data: &[u8]| {
    let image = Bytes(data);
    let Ok(container) = nixcavate_fs::apfs::Apfs::open(&image) else { return };
    for index in container.volumes().iter().map(|v| v.index).take(4) {
        let Ok(volume) = container.volume(index) else { continue };
        let mut files = Vec::new();
        let _ = volume.walk(&mut |node| files.push(node), &mut |_| {});
        let mut buf = [0u8; 4096];
        for node in files.iter().filter(|n| n.kind == Kind::File).take(16) {
            let _ = volume.read(node.inode, 0, &mut buf);
            let _ = volume.read(node.inode, node.size.saturating_sub(100), &mut buf);
        }
    }
});

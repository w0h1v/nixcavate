#![no_main]
use nixcavate_fuzz::fuzz_target;
use nixcavate_source::Source;
use std::path::PathBuf;
use std::sync::OnceLock;

fn dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("nixcavate-fuzz-vdisk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    })
}

// A hostile virtual disk (qcow2, VMDK sparse extent or descriptor, VHD, VHDX, VDI): opening it as
// evidence, listing its volumes and reading files from them must return, whatever the bytes are.
// The input is the file itself, so the seeds are the format fixtures (see fuzz/run.sh).
fuzz_target!(|data: &[u8]| {
    let dir = dir();
    let path = dir.join("disk");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let Ok(source) = Source::open(&path, &|_| true, dir) else { return };
    for entry in source.entries().iter().take(32) {
        let _ = source.read(entry);
    }
});

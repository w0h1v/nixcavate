//! `auto-parse` on virtual machine disks: every format and variant (made by `qemu-img` from one
//! raw disk, see `test_files/image/vdisk/build.sh`) must give the host and the records the raw
//! disk gives, and the unreadable ones must fail with the reason.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/vdisk")
}

fn unzst(name: &str) -> Vec<u8> {
    zstd::decode_all(&fs::read(fixtures().join(format!("{name}.zst"))).unwrap()[..]).unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nixcavate-vdisk-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn parse(image: &Path, out: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nixcavate"))
        .args(["auto-parse", "-f", image.to_str().unwrap(), "-o", out.to_str().unwrap(), "-t", "jsonl"])
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn manifest(out: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap()
}

/// Every file under the host's output folder, by relative path.
fn records(out: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, base: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, into);
            } else {
                into.insert(path.strip_prefix(base).unwrap().display().to_string(), fs::read(&path).unwrap());
            }
        }
    }
    let mut into = BTreeMap::new();
    walk(&out.join("imagehost"), &out.join("imagehost"), &mut into);
    into
}

#[test]
fn every_virtual_disk_format_gives_the_same_records_as_the_raw_disk() {
    let scratch = Scratch::new("formats");
    let raw = zstd::decode_all(&fs::read(fixtures().join("disk.img.zst")).unwrap()[..]).unwrap();
    fs::write(scratch.path("disk.img"), &raw).unwrap();
    let out = scratch.path("out-raw");
    let run = parse(&scratch.path("disk.img"), &out);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let expected = records(&out);
    assert!(expected.len() > 5, "{:?}", expected.keys());

    let names = [
        "qcow2-v3.qcow2",
        "qcow2-v2.qcow2",
        "qcow2-compressed.qcow2",
        "qcow2-zstd.qcow2",
        "qcow2-512.qcow2",
        "qcow2-2m.qcow2",
        "qcow2-extl2.qcow2",
        "vmdk-monolithicSparse.vmdk",
        "vmdk-streamOptimized.vmdk",
        "vmdk-twoGbMaxExtentSparse.vmdk",
        "vmdk-monolithicFlat.vmdk",
        "vmdk-twoGbMaxExtentFlat.vmdk",
        "vpc-dynamic.vhd",
        "vpc-fixed.vhd",
        "vhdx-dynamic.vhdx",
        "vhdx-1m.vhdx",
        "vdi-dynamic.vdi",
        "vdi-static.vdi",
    ];
    // The extents of the split and flat VMDKs.
    fs::write(scratch.path("vmdk-twoGbMaxExtentSparse-s001.vmdk"), unzst("vmdk-twoGbMaxExtentSparse-s001.vmdk"))
        .unwrap();
    fs::write(scratch.path("vmdk-monolithicFlat-flat.vmdk"), &raw).unwrap();
    fs::write(scratch.path("vmdk-twoGbMaxExtentFlat-f001.vmdk"), &raw).unwrap();
    for name in names {
        let image = scratch.path(name);
        fs::write(&image, unzst(name)).unwrap();
        let out = scratch.path(&format!("out-{name}"));
        let run = parse(&image, &out);
        assert!(run.status.success(), "{name}: {}", text(&run.stderr));
        let m = manifest(&out);
        assert_eq!(m["hosts"][0]["name"], "imagehost", "{name}");
        assert_eq!(m["hosts"][0]["root"], "p1/[root]", "{name}");
        let tasks = m["tasks"].as_array().unwrap();
        assert!(tasks.iter().all(|t| t["status"] == "succeeded"), "{name}: {tasks:?}");
        let got = records(&out);
        assert_eq!(got.keys().collect::<Vec<_>>(), expected.keys().collect::<Vec<_>>(), "{name}: files");
        for (path, content) in &expected {
            assert!(got[path] == *content, "{name}: {path} differs from the raw disk's");
        }
        assert!(
            text(&run.stderr).contains("virtual disk read directly"),
            "{name}: the format is not named: {}",
            text(&run.stderr)
        );
    }
}

#[test]
fn unreadable_virtual_disks_fail_with_the_reason() {
    let scratch = Scratch::new("refused");
    for (name, reason) in [
        ("qcow2-backing.qcow2", "backing file (base.raw)"),
        ("qcow2-luks.qcow2", "encrypted"),
        ("vmdk-child.vmdk", "has a parent (base.vmdk)"),
    ] {
        let image = scratch.path(name);
        fs::write(&image, unzst(name)).unwrap();
        let run = parse(&image, &scratch.path("out"));
        assert!(!run.status.success(), "{name}");
        assert!(text(&run.stderr).contains(reason), "{name}: {}", text(&run.stderr));
    }
}

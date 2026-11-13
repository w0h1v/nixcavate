//! Test support for the Kubernetes artifacts: the node trees and listings that
//! `test_files/k8s-real/build-k3s.sh` and `build-kind.sh` collected from real clusters.

use std::path::{Path, PathBuf};

pub fn root(flavor: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/k8s-real").join(flavor)
}

/// Every file under `<flavor>/node`, as (path relative to the node root, bytes), sorted.
pub fn node(flavor: &str) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for item in std::fs::read_dir(dir).unwrap().flatten() {
            let path = item.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_str().unwrap().to_string();
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    let base = root(flavor).join("node");
    let mut out = Vec::new();
    walk(&base, &base, &mut out);
    out.sort();
    out
}

pub fn expected(flavor: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root(flavor).join("expected.json")).unwrap()).unwrap()
}

/// The records of a `testing::run` output (the part before the timeline), as JSON values.
pub fn records(out: &str) -> Vec<serde_json::Value> {
    out.lines().take_while(|l| !l.starts_with("---")).map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// The containerd metadata file collected from the cluster, still gzip-compressed.
pub fn meta(flavor: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_files/containerd-containers")
        .join(format!("{flavor}-meta.db.gz"));
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&std::fs::read(path).unwrap()[..]), &mut out).unwrap();
    out
}

/// A file of the flavor's fixture folder (not under `node/`).
pub fn file_bytes(flavor: &str, name: &str) -> Vec<u8> {
    std::fs::read(root(flavor).join(name)).unwrap()
}

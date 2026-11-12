//! Test support: run a parser on fixture bytes and render everything it produced as text for
//! a snapshot. Public so integration tests and fuzz targets can use it.

use crate::{Artifact, Input};
use nixcavate_core::run::merge;
use nixcavate_core::{Error, Format, Sink};
use nixcavate_source::{discover, Source};
use std::path::{Path, PathBuf};

/// Reads a fixture from the repository's `test_files/` directory.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!("nixcavate-test-{}", std::process::id()))
}

/// Builds an input for `path` holding `data` on an otherwise empty host and calls `f`.
pub fn with_input<T>(path: &str, data: &[u8], mtime: i64, f: impl FnOnce(&Input) -> T) -> T {
    with_host(&[(path, data)], path, mtime, f)
}

/// Like [`with_input`], with more files on the host (companions, `etc/localtime`).
///
/// Paths are relative to the host root. A path starting with `../` is a file beside the root,
/// as in a UAC collection; the test host is then laid out like one (`[root]/` plus siblings).
pub fn with_host<T>(files: &[(&str, &[u8])], path: &str, mtime: i64, f: impl FnOnce(&Input) -> T) -> T {
    let uac_layout = files.iter().any(|(p, _)| p.starts_with("../"));
    let mut placed: Vec<(String, &[u8])> = files
        .iter()
        .map(|&(p, data)| match p.strip_prefix("../") {
            Some(beside) => (beside.to_string(), data),
            None if uac_layout => (format!("[root]/{p}"), data),
            None => (p.to_string(), data),
        })
        .collect();
    if uac_layout {
        placed.push(("uac.log".to_string(), b""));
    }
    let placed: Vec<(&str, &[u8])> = placed.iter().map(|(p, data)| (p.as_str(), *data)).collect();
    let source = Source::from_memory(&placed);
    let hosts = discover(&source, None);
    let host = hosts.first().expect("discover always yields a host");
    let data = host.read(path).unwrap_or_else(|| panic!("{path} is not among the test files"));
    f(&Input { host, path, data: &data, offset: 0, mtime, mode: 0o100644, uid: 0, gid: 0, scratch: &scratch() })
}

/// Runs the artifact's parser and returns its JSONL records, then its timeline as CSV, then
/// any warnings or error. This is the text that snapshot tests store.
pub fn run(artifact: &Artifact, path: &str, data: &[u8], mtime: i64) -> String {
    run_on_host(artifact, &[(path, data)], path, mtime)
}

/// Like [`run`], with more files on the host.
pub fn run_on_host(artifact: &Artifact, files: &[(&str, &[u8])], path: &str, mtime: i64) -> String {
    with_host(files, path, mtime, |input| {
        let mut sink = Sink::memory(&input.host.name, artifact.id, path, Format::Jsonl);
        let result = (artifact.parse)(input, &mut sink);
        let summary = sink.finish().expect("an in-memory sink cannot fail");
        let mut out = String::from_utf8(summary.memory).expect("records are UTF-8");
        if !summary.memory_run.is_empty() {
            out.push_str("--- timeline ---\n");
            let mut timeline = Vec::new();
            merge(&[&summary.memory_run], Format::Csv, 1, &mut timeline).expect("the run was just written");
            out.push_str(&String::from_utf8(timeline).expect("the timeline is UTF-8"));
        }
        for warning in summary.warnings {
            out.push_str(&format!("--- warning: {warning}\n"));
        }
        match result {
            Ok(()) => {}
            Err(Error::Skipped(why)) => out.push_str(&format!("--- skipped: {why}\n")),
            Err(e) => out.push_str(&format!("--- failed: {e}\n")),
        }
        out
    })
}

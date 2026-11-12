//! Turns hosts and artifacts into tasks: one per file, or one per chunk of a large text file.

use nixcavate_artifacts::{artifacts, text, Artifact};
use nixcavate_source::host::DISCOVERY_PATHS;
use nixcavate_source::{Data, Entry, Host, Os, Pattern};
use std::collections::{BTreeMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

/// Target size of one chunk of a split text file.
const CHUNK_BYTES: usize = 64 << 20;

pub struct Task<'a> {
    pub host_index: usize,
    pub host: &'a Host<'a>,
    pub artifact: &'static Artifact,
    pub entry: &'a Entry,
    /// Input path relative to the host root.
    pub rel: String,
    /// File-system-safe name for this task's outputs, unique within host and artifact.
    pub name: String,
    /// The part of the file this task parses, when the file was split.
    pub chunk: Option<(Arc<Data>, Range<usize>)>,
    pub bytes: u64,
}

impl Task<'_> {
    pub fn offset(&self) -> u64 {
        self.chunk.as_ref().map_or(0, |(_, range)| range.start as u64)
    }

    /// Estimated work, for scheduling the largest tasks first.
    fn cost(&self) -> f64 {
        self.bytes as f64 * self.artifact.cost as f64
    }
}

/// The paths a compressed tar must keep while it streams by: everything any artifact or host
/// discovery could read, matched under any prefix because host roots are not known yet.
pub fn keep_patterns() -> Vec<Pattern> {
    let artifact_paths = artifacts().flat_map(|a| a.paths.iter().chain(a.companions));
    artifact_paths.chain(DISCOVERY_PATHS).map(|p| Pattern::new(p)).collect()
}

/// Plans every task, largest first. `selected` filters artifacts (`--only`, `--skip`).
pub fn plan<'a>(hosts: &'a [Host<'a>], selected: &dyn Fn(&Artifact) -> bool) -> Vec<Task<'a>> {
    let mut tasks = Vec::new();
    for (host_index, host) in hosts.iter().enumerate() {
        for artifact in artifacts().filter(|a| selected(a)) {
            if host.os != Os::Unknown && !artifact.os.contains(&host.os) {
                continue;
            }
            // Keyed by path so a file matched by two patterns is parsed once.
            let mut matches = BTreeMap::new();
            for pattern in artifact.paths {
                let pattern = Pattern::new(pattern);
                // Links are skipped: their targets are matched as files in their own right.
                matches.extend(host.find(&pattern).filter(|e| e.link.is_none()).map(|e| (e.path.as_str(), e)));
            }
            let mut names = HashSet::new();
            for entry in matches.into_values() {
                let rel = host.rel(entry);
                for chunk in split(host, artifact, entry) {
                    let offset = chunk.as_ref().map_or(0, |(_, range): &(_, Range<usize>)| range.start);
                    let bytes = chunk.as_ref().map_or(entry.size, |(_, range)| range.len() as u64);
                    let name = unique_name(&rel, offset, &mut names);
                    tasks.push(Task { host_index, host, artifact, entry, rel: rel.clone(), name, chunk, bytes });
                }
            }
        }
    }
    // Longest processing time first; ties in a fixed order so runs are repeatable.
    tasks.sort_by(|a, b| {
        b.cost().total_cmp(&a.cost()).then_with(|| {
            (a.host_index, a.artifact.id, &a.rel, a.offset()).cmp(&(b.host_index, b.artifact.id, &b.rel, b.offset()))
        })
    });
    tasks
}

/// One `None` for a file parsed whole, or its chunks when it is large, plain and line-based.
fn split(host: &Host, artifact: &Artifact, entry: &Entry) -> Vec<Option<(Arc<Data>, Range<usize>)>> {
    if !artifact.split_lines || entry.size <= CHUNK_BYTES as u64 {
        return vec![None];
    }
    let Ok(data) = host.open(entry) else { return vec![None] };
    if text::is_compressed(&data) {
        return vec![None];
    }
    let data = Arc::new(data);
    chunk_ranges(&data, CHUNK_BYTES).into_iter().map(|range| Some((data.clone(), range))).collect()
}

/// Cuts `data` into ranges of about `chunk` bytes that each end just after a newline, so no
/// line is ever split between two tasks.
fn chunk_ranges(data: &[u8], chunk: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let target = (start + chunk).min(data.len());
        let end = memchr::memchr(b'\n', &data[target..]).map_or(data.len(), |i| target + i + 1);
        ranges.push(start..end);
        start = end;
    }
    ranges
}

/// A file name derived from the input path. Different paths can flatten to the same name
/// (`a/b_c` and `a_b/c`), so a clash gets a hash of the real path appended.
fn unique_name(rel: &str, offset: usize, taken: &mut HashSet<String>) -> String {
    let hash = rel.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3));
    let flat: String = rel
        .trim_start_matches("../")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect();
    let mut name = flat.trim_start_matches(['.', '_']).to_string();
    if name.len() > 120 {
        name = format!("{}-{hash:016x}", &name[name.len() - 100..]);
    }
    if offset > 0 {
        name = format!("{name}@{offset}");
    }
    // Names are compared without case: the output may sit on a case-insensitive filesystem,
    // where `Alice` and `alice` would be one file.
    if name.is_empty() || !taken.insert(name.to_ascii_lowercase()) {
        name = format!("{name}-{hash:016x}");
        taken.insert(name.to_ascii_lowercase());
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_cover_the_data_and_end_on_line_boundaries() {
        let data: Vec<u8> = (0..500).flat_map(|n| format!("line {n} {}\n", "x".repeat(n % 37)).into_bytes()).collect();
        for chunk in [1, 7, 64, 1000, data.len(), data.len() * 2] {
            let ranges = chunk_ranges(&data, chunk);
            assert_eq!(ranges.first().map(|r| r.start), Some(0));
            assert_eq!(ranges.last().map(|r| r.end), Some(data.len()));
            assert!(ranges.windows(2).all(|w| w[0].end == w[1].start), "no gap and no overlap");
            assert!(ranges.iter().all(|r| data[r.end - 1] == b'\n'));
            assert!(ranges.iter().rev().skip(1).all(|r| r.len() >= chunk), "only the last chunk may be short");
            let lines: usize = ranges.iter().map(|r| data[r.clone()].split(|&b| b == b'\n').count() - 1).sum();
            assert_eq!(lines, 500, "every line is in exactly one chunk");
        }
        assert_eq!(chunk_ranges(b"no newline at all", 4), vec![0..17]);
        assert!(chunk_ranges(b"", 4).is_empty());
    }

    #[test]
    fn names_are_safe_and_unique() {
        let mut taken = HashSet::new();
        assert_eq!(unique_name("var/log/auth.log.1", 0, &mut taken), "var_log_auth.log.1");
        assert_eq!(unique_name("home/a b/.bash_history", 0, &mut taken), "home_a_b_.bash_history");
        let clash = unique_name("home/a_b/.bash_history", 0, &mut taken);
        assert!(clash.starts_with("home_a_b_.bash_history-") && clash.len() > 30, "{clash}");
        assert_eq!(unique_name("../live_response/ps.txt", 0, &mut taken), "live_response_ps.txt");
        assert_eq!(unique_name("var/log/big.log", 67_108_900, &mut taken), "var_log_big.log@67108900");
        let other_case = unique_name("home/A_B/.bash_history", 0, &mut taken);
        assert!(other_case.starts_with("home_A_B_.bash_history-"), "{other_case}");
        let long = unique_name(&"x/".repeat(200), 0, &mut taken);
        assert!(long.len() < 130, "{long}");
    }
}

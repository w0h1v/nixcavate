//! The artifact parsers. Each artifact is one module that exports one `ARTIFACT` value; adding
//! an artifact means writing that module and adding one line to its OS registry.

pub mod common;
pub mod linux;
pub mod logical_lines;
pub mod macos;
pub mod sqlite;
pub mod testing;
pub mod text;

use nixcavate_core::{Basis, Precision, Result, Sink, Timestamp};
use nixcavate_source::{Host, Os};
use std::path::Path;

/// The output folder an artifact's results go to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Accounts,
    Logs,
    Execution,
    Persistence,
    Software,
    Network,
    Filesystem,
    Containers,
    Activity,
    Security,
    System,
    Live,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Accounts => "Accounts",
            Category::Logs => "Logs",
            Category::Execution => "Execution",
            Category::Persistence => "Persistence",
            Category::Software => "Software",
            Category::Network => "Network",
            Category::Filesystem => "Filesystem",
            Category::Containers => "Containers",
            Category::Activity => "Activity",
            Category::Security => "Security",
            Category::System => "System",
            Category::Live => "Live",
        }
    }
}

/// One file (or one chunk of a large file) handed to a parser.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub host: &'a Host<'a>,
    /// Path relative to the host root.
    pub path: &'a str,
    /// The raw bytes, exactly as stored (possibly compressed; see [`text`]).
    pub data: &'a [u8],
    /// Where `data` starts in the file. Non-zero only for chunks of a split file.
    pub offset: u64,
    /// The file's modification time in seconds since the epoch; 0 when unknown.
    pub mtime: i64,
    /// Unix permission bits and owner, as collected. 0 when the source does not record them.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// A directory for temporary files (SQLite copies). Removed after the run.
    pub scratch: &'a Path,
}

impl Input<'_> {
    /// A timestamp for a wall-clock time that carries no zone: the host zone is applied (UTC
    /// when the host zone is unknown) and the result is marked `AssumedZone`.
    pub fn local_time(&self, wall_secs: i64, nanos: u32, precision: Precision) -> Timestamp {
        Timestamp::from_secs_nanos(self.host.tz.to_utc(wall_secs), nanos, precision, Basis::AssumedZone)
    }
}

pub type ParseFn = fn(&Input, &mut Sink) -> Result<()>;

/// An artifact: where its files are and how to parse one.
pub struct Artifact {
    /// Stable identifier, used on the command line and in output paths.
    pub id: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub os: &'static [Os],
    /// Patterns for the files to parse; one task per match. See [`nixcavate_source::glob`].
    pub paths: &'static [&'static str],
    /// Patterns for files the parser reads through `Input::host` (lookup tables, SQLite
    /// write-ahead logs). They are kept available but do not become tasks.
    pub companions: &'static [&'static str],
    /// Relative work per input byte, from benchmarks. Schedules the largest tasks first.
    pub cost: f32,
    /// True when each line parses on its own, so a large file can be split at newlines and
    /// its chunks parsed in parallel. Such parsers must locate records by offset, not line.
    pub split_lines: bool,
    pub parse: ParseFn,
}

impl Artifact {
    pub const fn new(
        id: &'static str,
        description: &'static str,
        category: Category,
        os: &'static [Os],
        paths: &'static [&'static str],
        parse: ParseFn,
    ) -> Self {
        Self { id, description, category, os, paths, companions: &[], cost: 1.0, split_lines: false, parse }
    }

    pub const fn companions(mut self, companions: &'static [&'static str]) -> Self {
        self.companions = companions;
        self
    }

    pub const fn cost(mut self, cost: f32) -> Self {
        self.cost = cost;
        self
    }

    pub const fn split_lines(mut self) -> Self {
        self.split_lines = true;
        self
    }
}

/// Every artifact, in listing order.
pub fn artifacts() -> impl Iterator<Item = &'static Artifact> {
    linux::ARTIFACTS.iter().chain(macos::ARTIFACTS).chain(common::ARTIFACTS)
}

pub fn find(id: &str) -> Option<&'static Artifact> {
    artifacts().find(|a| a.id == id)
}

pub const LINUX: &[Os] = &[Os::Linux];
pub const MACOS: &[Os] = &[Os::Macos];
pub const ANY_OS: &[Os] = &[Os::Linux, Os::Macos];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn artifact_ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for artifact in artifacts() {
            assert!(seen.insert(artifact.id), "duplicate artifact id {}", artifact.id);
            assert!(
                artifact.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "artifact id {} must be lowercase kebab-case",
                artifact.id
            );
            assert!(!artifact.paths.is_empty(), "{} has no paths", artifact.id);
            assert!(!artifact.description.is_empty(), "{} has no description", artifact.id);
            assert!(artifact.cost > 0.0);
        }
    }
}

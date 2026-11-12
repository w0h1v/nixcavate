//! `manifest.json`: what a run did, task by task. Field names are part of the output contract.

use serde::{Deserialize, Serialize};

/// Bumped when a field is removed or changes meaning.
pub const SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub tool_version: String,
    /// RFC 3339, UTC.
    pub started: String,
    pub duration_ms: u64,
    pub threads: usize,
    pub format: String,
    pub hosts: Vec<HostEntry>,
    pub tasks: Vec<TaskEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostEntry {
    pub name: String,
    pub os: String,
    pub os_version: String,
    /// The evidence path this host was read from.
    pub source: String,
    /// The host root inside the source (`[root]` for UAC).
    pub root: String,
    /// How local times were converted, e.g. `Europe/Berlin (etc/localtime)` or `UTC (assumed)`.
    pub timezone: String,
    /// Output directory, relative to the manifest.
    pub output_dir: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Succeeded,
    Skipped,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskEntry {
    pub host: String,
    pub artifact: String,
    /// Source path relative to the host root.
    pub input: String,
    /// Start of this task's chunk when a large file was split; otherwise 0.
    pub input_offset: u64,
    pub input_bytes: u64,
    pub status: Status,
    /// Why the task was skipped or failed.
    pub error: Option<String>,
    pub duration_ms: u64,
    pub records: u64,
    pub records_per_sec: u64,
    pub events: u64,
    /// The earliest and latest timeline event this task produced (RFC 3339). For a task that
    /// failed part-way, this is the span that was parsed.
    #[serde(default)]
    pub first_event: Option<String>,
    #[serde(default)]
    pub last_event: Option<String>,
    /// The input file's modification time as collected: roughly when a log was last written.
    /// With `last_event` it bounds what a failed or skipped log may hold that was not parsed.
    #[serde(default)]
    pub input_modified: Option<String>,
    pub warnings: Vec<String>,
    /// Paths relative to the manifest.
    pub outputs: Vec<String>,
    pub timeline_runs: Vec<String>,
}

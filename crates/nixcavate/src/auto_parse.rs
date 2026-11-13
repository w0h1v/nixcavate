//! `auto-parse` and `parse`: open the evidence, find hosts, plan tasks, run them, report.

use crate::exec::{execute, Settings};
use crate::plan::{keep_patterns, plan, Task};
use crate::report::printable;
use crate::{report, Common, ParseArgs, EXIT_OK, EXIT_PARTIAL};
use nixcavate_artifacts::Artifact;
use nixcavate_core::manifest::{HostEntry, Manifest, Status, MANIFEST_NAME, SCHEMA_VERSION};
use nixcavate_core::{Basis, Format, Target, Timestamp};
use nixcavate_source::{discover, Host, Os, Source};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Options {
    pub evidence: PathBuf,
    pub output: PathBuf,
    pub only: Vec<String>,
    pub skip: Vec<String>,
    pub common: Common,
}

/// Folder inside each host's output that holds its sorted timeline runs.
const RUNS_DIR: &str = "_timeline";
/// Archives and disk images (the first E01 segment, raw images) found directly in a directory.
const ARCHIVE_SUFFIXES: [&str; 14] = [
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.zst", ".tar.xz", ".txz", ".zip", ".e01", ".dd", ".raw",
    ".img", ".001",
];

pub fn run(options: &Options) -> Result<u8, String> {
    let manifest = parse_all(options)?;
    if !options.common.quiet {
        report::print_summary(&manifest, &options.output, !options.common.no_color);
    }
    let failed = manifest.tasks.iter().any(|t| t.status == Status::Failed);
    Ok(if failed { EXIT_PARTIAL } else { EXIT_OK })
}

/// Parses the evidence into `options.output` and returns the manifest it wrote there.
pub fn parse_all(options: &Options) -> Result<Manifest, String> {
    let started = Instant::now();
    let started_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let common = &options.common;
    let format = Format::from(common.output_type);
    let selected = selection(&options.only, &options.skip)?;
    nixcavate_source::set_expansion_limit(common.max_expansion);
    check_separate(&options.evidence, &options.output)?;
    prepare_output(&options.output, common.clobber)?;
    let scratch = options.output.join(".scratch");

    let sources = open_sources(&options.evidence, &options.output, &scratch)?;
    let zoneinfo = common.zoneinfo.is_dir().then_some(common.zoneinfo.as_path());
    let hosts: Vec<Host> = sources.iter().flat_map(|source| discover(source, zoneinfo)).collect();
    let tasks = plan(&hosts, &|a| selected(a));

    // A host of unknown layout with nothing to parse is just a folder that held archives.
    let used: HashSet<usize> = tasks.iter().map(|t| t.host_index).collect();
    let mut taken: HashSet<String> = RESERVED_NAMES.iter().map(|name| name.to_string()).collect();
    let dirs: Vec<Option<String>> = hosts
        .iter()
        .enumerate()
        .map(|(i, host)| (host.os != Os::Unknown || used.contains(&i)).then(|| unique_dir(&host.name, &mut taken)))
        .collect();

    if dirs.iter().all(Option::is_none) {
        let _ = fs::remove_dir_all(&scratch);
        return Err(format!(
            "no host found in {}: nothing in it looks like a supported system (etc/, var/log/, var/adm/, \
             System/Library/). A collection made of archives inside an archive must be extracted first",
            options.evidence.display()
        ));
    }

    let threads = common.threads.unwrap_or_else(|| thread::available_parallelism().map_or(1, |n| n.get())).max(1);
    let target = |task: &Task| {
        let host_dir = options.output.join(dirs[task.host_index].as_deref().unwrap_or("host"));
        let file = format!("{}.{}", task.name, format.extension());
        let records = host_dir.join(task.artifact.category.as_str()).join(task.artifact.id).join(file);
        (Target::File(records), Some(host_dir.join(RUNS_DIR).join(task.artifact.id).join(&task.name)))
    };
    let settings = Settings { format, threads, scratch: &scratch, output_root: &options.output, target: &target };
    let mut entries = execute(&tasks, &settings);
    let _ = fs::remove_dir_all(&scratch);

    // Tasks ran largest first; the manifest lists them in a stable order instead.
    entries.sort_by(|a, b| {
        (&a.host, &a.artifact, &a.input, a.input_offset).cmp(&(&b.host, &b.artifact, &b.input, b.input_offset))
    });
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started: Timestamp::from_secs(started_at, Basis::Recorded).to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        threads,
        format: format.extension().to_string(),
        hosts: hosts
            .iter()
            .zip(&dirs)
            .filter_map(|(host, dir)| {
                Some(HostEntry {
                    name: host.name.clone(),
                    os: host.os.as_str().to_string(),
                    os_version: host.os_version.clone(),
                    source: host.source.path.display().to_string(),
                    root: host.root.clone(),
                    timezone: host.tz_description.clone(),
                    output_dir: dir.clone()?,
                })
            })
            .collect(),
        tasks: entries,
    };
    fs::create_dir_all(&options.output).map_err(|e| format!("{}: {e}", options.output.display()))?;
    let manifest_path = options.output.join(MANIFEST_NAME);
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    fs::write(&manifest_path, json).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    Ok(manifest)
}

/// `parse <artifact>`: one file to a file or stdout, or a filtered `auto-parse` with `-d`.
pub fn run_parse(args: ParseArgs) -> Result<u8, String> {
    let artifact = nixcavate_artifacts::find(&args.artifact)
        .ok_or_else(|| format!("unknown artifact `{}`; see `nixcavate list`", args.artifact))?;
    if let Some(directory) = args.directory {
        let output = args.output.ok_or("parse -d needs an output directory (-o)")?;
        return run(&Options {
            evidence: directory,
            output,
            only: vec![args.artifact],
            skip: vec![],
            common: args.common,
        });
    }
    let file = args.file.expect("clap requires one of -f and -d");
    if let Some(output) = &args.output {
        if output.exists() && !args.common.clobber {
            return Err(format!("{} exists; pass -C to replace it", output.display()));
        }
    }
    nixcavate_source::set_expansion_limit(args.common.max_expansion);
    let source = Source::single_file(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let hosts = discover(&source, None);
    let (host, entry) = (&hosts[0], &source.entries()[0]);
    let task = Task {
        host_index: 0,
        host,
        artifact,
        entry,
        rel: entry.path.clone(),
        name: String::new(),
        chunk: None,
        bytes: entry.size,
    };
    let scratch = private_temp_dir("nixcavate-parse").map_err(|e| format!("cannot create a scratch directory: {e}"))?;
    if let Some(output) = &args.output {
        // Checked above: the file is absent, or the user asked to replace it.
        let _ = fs::remove_file(output);
    }
    let target = |_: &Task| match &args.output {
        Some(path) => (Target::File(path.clone()), None),
        None => (Target::Stdout, None),
    };
    let settings = Settings {
        format: args.common.output_type.into(),
        threads: 1,
        scratch: &scratch,
        output_root: Path::new(""),
        target: &target,
    };
    let entry = execute(&[task], &settings).pop().ok_or("the task did not run")?;
    let _ = fs::remove_dir_all(&scratch);
    for warning in &entry.warnings {
        eprintln!("warning: {}", printable(warning));
    }
    match (entry.status, entry.error) {
        (Status::Failed, error) => {
            eprintln!("failed: {}", printable(&error.unwrap_or_default()));
            Ok(EXIT_PARTIAL)
        }
        (Status::Skipped, error) => {
            eprintln!("skipped: {}", printable(&error.unwrap_or_default()));
            Ok(EXIT_OK)
        }
        (Status::Succeeded, _) => Ok(EXIT_OK),
    }
}

/// A new directory under the system temp directory that only this user can enter. The name
/// is not predictable and creation fails if it exists, so another local user cannot plant
/// files or links in it first.
pub fn private_temp_dir(label: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let mut last = None;
    for attempt in 0..16u32 {
        let name =
            format!("{label}-{}-{:08x}", std::process::id(), nanos.wrapping_add(attempt).wrapping_mul(0x9E37_79B9));
        let path = std::env::temp_dir().join(name);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no free name")))
}

/// The artifact filter for `--only` and `--skip`. Unknown ids are an error, not a silent no-op.
fn selection(only: &[String], skip: &[String]) -> Result<impl Fn(&Artifact) -> bool, String> {
    for id in only.iter().chain(skip) {
        if nixcavate_artifacts::find(id).is_none() {
            return Err(format!("unknown artifact `{id}`; see `nixcavate list`"));
        }
    }
    let (only, skip) = (only.to_vec(), skip.to_vec());
    Ok(move |a: &Artifact| (only.is_empty() || only.iter().any(|id| id == a.id)) && !skip.iter().any(|id| id == a.id))
}

/// Refuses to mix two runs. With `--clobber`, removes exactly what the earlier run's manifest
/// says it created, and nothing else.
fn prepare_output(output: &Path, clobber: bool) -> Result<(), String> {
    let manifest_path = output.join(MANIFEST_NAME);
    if !manifest_path.exists() {
        return Ok(());
    }
    if !clobber {
        return Err(format!("{} already holds a run; pass -C to replace it", output.display()));
    }
    let old: Option<Manifest> = fs::read(&manifest_path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok());
    for host in old.iter().flat_map(|m| &m.hosts) {
        let dir = Path::new(&host.output_dir);
        // Only a plain folder name directly inside the output directory is ever removed.
        if dir.components().count() == 1 && dir.file_name().is_some() {
            let _ = fs::remove_dir_all(output.join(dir));
        }
    }
    fs::remove_file(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))
}

/// How far below an evidence folder archives are looked for when it holds no host itself
/// (fastir writes `<folder>/<run>/<host>-files.zip`), counted in path components, and how many
/// directory entries that search examines before it stops.
const DEEPEST: usize = 3;
const EXAMINED: usize = 4096;

/// The archives and images in `dir` and, up to `DEEPEST` components down, in its folders.
/// Only regular files and real folders are followed (a link may point out of the evidence),
/// and the output folder is never entered.
fn archives_below(dir: &Path, output: &Path) -> Vec<PathBuf> {
    let (mut found, mut examined) = (Vec::new(), 0usize);
    let mut level = vec![dir.to_path_buf()];
    for depth in 1..=DEEPEST {
        let mut next = Vec::new();
        for folder in &level {
            let Ok(listing) = fs::read_dir(folder) else { continue };
            let mut items: Vec<_> = listing.flatten().collect();
            items.sort_by_key(|item| item.file_name());
            for item in items {
                examined += 1;
                if examined > EXAMINED {
                    eprintln!("nixcavate: {}: stopped looking for archives after {EXAMINED} entries", dir.display());
                    return found;
                }
                let Ok(kind) = item.file_type() else { continue };
                let path = item.path();
                if kind.is_dir() && depth < DEEPEST && resolved(&path) != resolved(output) {
                    next.push(path);
                } else if kind.is_file() {
                    let name = item.file_name().to_string_lossy().to_ascii_lowercase();
                    if ARCHIVE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
                        found.push(path);
                    }
                }
            }
        }
        level = next;
    }
    found
}

/// Opens each path as a source, listing archives in parallel (decompressing a tar stream is
/// single-threaded). `first` is the path the user named: it must open; a stray bad archive
/// beside it is reported and skipped. `index` numbers the scratch folders.
fn open_all(paths: &[PathBuf], first: Option<&Path>, index: usize, scratch: &Path) -> Result<Vec<Source>, String> {
    let patterns = keep_patterns();
    let keep = |path: &str| patterns.iter().any(|p| p.matches_suffix(path));
    let opened: Vec<_> = thread::scope(|scope| {
        let handles: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let keep = &keep;
                scope.spawn(move || Source::open(path, keep, &scratch.join(format!("source-{}", index + i))))
            })
            .collect();
        handles.into_iter().map(|h| h.join()).collect()
    });
    let mut sources = Vec::new();
    for (path, result) in paths.iter().zip(opened) {
        match result {
            Ok(Ok(source)) => {
                for warning in &source.warnings {
                    eprintln!("nixcavate: {}: {warning}", path.display());
                }
                sources.push(source)
            }
            Ok(Err(e)) if Some(path.as_path()) == first => return Err(format!("{}: {e}", path.display())),
            Ok(Err(e)) => eprintln!("nixcavate: skipping {}: {e}", path.display()),
            Err(_) => return Err(format!("{}: reading the archive panicked", path.display())),
        }
    }
    Ok(sources)
}

/// The evidence itself, plus any archives directly inside an evidence directory. A directory
/// that holds no host (not itself, and none in the archives beside it) is searched further
/// down for archives and images, so a tool's `<folder>/<run>/<host>-files.zip` is found.
fn open_sources(evidence: &Path, output: &Path, scratch: &Path) -> Result<Vec<Source>, String> {
    let mut paths = vec![evidence.to_path_buf()];
    if evidence.is_dir() {
        let listing = fs::read_dir(evidence).map_err(|e| format!("{}: {e}", evidence.display()))?;
        let mut archives: Vec<PathBuf> = listing
            .flatten()
            // Not `is_file()`: that follows symlinks, and a link here may point out of the evidence.
            .filter(|item| item.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|item| item.path())
            .filter(|path| {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
                ARCHIVE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
            })
            .collect();
        archives.sort();
        paths.extend(archives);
    }
    let mut sources = open_all(&paths, Some(evidence), 0, scratch)?;
    if evidence.is_dir() && !sources.iter().any(|source| discover(source, None).iter().any(|h| h.os != Os::Unknown)) {
        let deeper: Vec<PathBuf> =
            archives_below(evidence, output).into_iter().filter(|p| !paths.contains(p)).collect();
        sources.extend(open_all(&deeper, None, paths.len(), scratch)?);
    }
    Ok(sources)
}

/// A folder name for a host: its name made file-system-safe, numbered if two hosts share it.
fn unique_dir(name: &str, taken: &mut HashSet<String>) -> String {
    let safe: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    let safe = match safe.trim_matches('.') {
        "" => "host".to_string(),
        trimmed => trimmed.to_string(),
    };
    let mut candidate = safe.clone();
    let mut n = 2;
    // Compared without case, for case-insensitive filesystems.
    while !taken.insert(candidate.to_ascii_lowercase()) {
        candidate = format!("{safe}-{n}");
        n += 1;
    }
    candidate
}

/// Names in the output directory that a host folder must not take.
const RESERVED_NAMES: [&str; 4] = [MANIFEST_NAME, "timeline.csv", "timeline.json", "timeline.jsonl"];

/// `path` made absolute with symlinks resolved, even when its last parts do not exist yet.
fn resolved(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        if let Ok(real) = existing.canonicalize() {
            return missing.iter().rev().fold(real, |p, part| p.join(part));
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_os_string());
                existing = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// A run must not write into the evidence it reads, nor read its own output as evidence.
fn check_separate(evidence: &Path, output: &Path) -> Result<(), String> {
    let (evidence, output) = (resolved(evidence), resolved(output));
    if output.starts_with(&evidence) || evidence.starts_with(&output) {
        return Err(format!(
            "the output directory {} and the evidence {} must not contain each other",
            output.display(),
            evidence.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_dirs_are_safe_and_unique() {
        let mut taken = HashSet::new();
        assert_eq!(unique_dir("web01", &mut taken), "web01");
        assert_eq!(unique_dir("web01", &mut taken), "web01-2");
        assert_eq!(unique_dir("../evil name", &mut taken), "_evil_name");
        assert_eq!(unique_dir("..", &mut taken), "host");
        assert_eq!(unique_dir("WEB01", &mut taken), "WEB01-3", "case-insensitive filesystems");
    }

    #[test]
    fn output_and_evidence_must_be_separate() {
        let base = private_temp_dir("nixcavate-separate-test").unwrap();
        fs::create_dir_all(base.join("case/sub")).unwrap();
        assert!(check_separate(&base.join("case"), &base.join("case/out")).is_err());
        assert!(check_separate(&base.join("case"), &base.join("case")).is_err());
        assert!(check_separate(&base.join("case/sub"), &base.join("case")).is_err());
        assert!(check_separate(&base.join("case"), &base.join("out/new/deeper")).is_ok());
        assert!(
            check_separate(&base.join("case"), &base.join("case-out")).is_ok(),
            "a shared name prefix is not containment"
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn unknown_artifact_ids_are_rejected() {
        assert!(selection(&["no-such-artifact".into()], &[]).is_err());
        let only_passwd = selection(&["passwd".into()], &[]).unwrap();
        assert!(only_passwd(nixcavate_artifacts::find("passwd").unwrap()));
        assert!(!only_passwd(nixcavate_artifacts::find("wtmp").unwrap()));
    }
}

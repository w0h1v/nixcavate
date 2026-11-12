//! `super-timeline`: a parallel merge of the sorted runs that `auto-parse` already wrote,
//! plus imported Sigma detections. No artifact is parsed again.

use crate::sigma;
use crate::{OutputType, EXIT_OK};
use clap::Args;
use nixcavate_core::manifest::{Manifest, MANIFEST_NAME};
use nixcavate_core::run::merge;
use nixcavate_core::Format;
use nixcavate_source::map_file;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[derive(Args)]
pub struct TimelineArgs {
    /// Output directory of an `auto-parse` run
    #[arg(short, long, value_name = "DIR")]
    directory: PathBuf,
    /// Timeline file [default: <DIR>/timeline.<type>]
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Output type
    #[arg(short = 't', long = "type", value_enum, default_value = "csv")]
    output_type: OutputType,
    /// ChopChopGo or Zircolite JSON results to merge in (repeatable)
    #[arg(long, value_name = "FILE")]
    sigma: Vec<PathBuf>,
    /// Worker threads [default: logical CPUs]
    #[arg(short = 'T', long)]
    threads: Option<usize>,
    /// Replace an existing timeline file
    #[arg(short = 'C', long)]
    clobber: bool,
    /// Print nothing but errors
    #[arg(short, long)]
    quiet: bool,
}

pub fn run(args: &TimelineArgs) -> Result<u8, String> {
    let started = Instant::now();
    let format = Format::from(args.output_type);
    let manifest_path = args.directory.join(MANIFEST_NAME);
    let manifest: Manifest = fs::read(&manifest_path)
        .map_err(|e| format!("{}: {e} (is this an auto-parse output directory?)", manifest_path.display()))
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", manifest_path.display())))?;
    let output = args.output.clone().unwrap_or_else(|| args.directory.join(format!("timeline.{}", format.extension())));
    if output.exists() && !args.clobber {
        return Err(format!("{} exists; pass -C to replace it", output.display()));
    }

    // Runs are mapped, not read: the merge touches each page once and the OS can drop it.
    // A mapping holds no file descriptor, so thousands of runs do not hit the open-file limit.
    let mut maps = Vec::new();
    for run in manifest.tasks.iter().flat_map(|t| &t.timeline_runs) {
        // The manifest is read back from disk: its paths must stay inside the run directory.
        if !Path::new(run).components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("{}: unexpected run path `{run}`", manifest_path.display()));
        }
        let path = args.directory.join(run);
        maps.push(map_file(&path).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    // Sigma results do not name their host; with one host in the run, it is that one.
    let host = match manifest.hosts.as_slice() {
        [only] => only.name.as_str(),
        _ => "",
    };
    let mut imported = Vec::new();
    for path in &args.sigma {
        let result = sigma::import(path, host).map_err(|e| format!("{}: {e}", path.display()))?;
        if result.skipped > 0 {
            eprintln!("nixcavate: {}: {} detections skipped (no readable time)", path.display(), result.skipped);
        }
        if !args.quiet {
            println!("{} detections from {}", result.events, path.display());
        }
        imported.push(result.run);
    }
    let runs: Vec<&[u8]> = maps.iter().map(|m| &m[..]).chain(imported.iter().map(|r| &r[..])).collect();

    let file = File::create(&output).map_err(|e| format!("{}: {e}", output.display()))?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let threads = args.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let rows = merge(&runs, format, threads, &mut writer).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| format!("{}: {e}", output.display()))?;
    if !args.quiet {
        println!(
            "{rows} events from {} runs in {:.2} s -> {}",
            runs.len(),
            started.elapsed().as_secs_f64(),
            output.display()
        );
    }
    Ok(EXIT_OK)
}

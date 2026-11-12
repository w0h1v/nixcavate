//! nixcavate: a fast forensic artifact parser for Linux and macOS collections.

mod auto_parse;
mod exec;
mod hunt;
mod hunt_checks;
mod list;
mod plan;
mod report;
mod sigma;
mod timeline;

use clap::{Args, Parser, Subcommand, ValueEnum};
use nixcavate_core::Format;
use std::path::PathBuf;
use std::process::ExitCode;

// Required for static musl builds, whose own allocator is slow under threads.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// All tasks succeeded or were skipped.
const EXIT_OK: u8 = 0;
/// The run finished but some tasks failed.
const EXIT_PARTIAL: u8 = 1;
/// The run could not start.
const EXIT_USAGE: u8 = 2;

#[derive(Parser)]
#[command(name = "nixcavate", version, about, max_term_width = 100)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find each host in the evidence, run every parser, write per-host results and manifest.json
    AutoParse(AutoParseArgs),
    /// Run one parser on one file (-f) or on every match in a directory or archive (-d)
    Parse(ParseArgs),
    /// Merge the timeline events of a parsed run, and imported Sigma results, into one sorted file
    SuperTimeline(timeline::TimelineArgs),
    /// Run persistence checks mapped to ATT&CK, with a YAML allow/block profile
    PersistenceHunter(hunt::HuntArgs),
    /// Show every artifact, its OS, its category and the paths it reads
    List(list::ListArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputType {
    Csv,
    Json,
    Jsonl,
}

impl From<OutputType> for Format {
    fn from(t: OutputType) -> Format {
        match t {
            OutputType::Csv => Format::Csv,
            OutputType::Json => Format::Json,
            OutputType::Jsonl => Format::Jsonl,
        }
    }
}

/// Options shared by the commands that parse evidence.
#[derive(Args)]
struct Common {
    /// Output type
    #[arg(short = 't', long = "type", value_enum, default_value = "csv")]
    output_type: OutputType,
    /// Worker threads [default: logical CPUs]
    #[arg(short = 'T', long)]
    threads: Option<usize>,
    /// Replace the results of an earlier run in the output directory
    #[arg(short = 'C', long)]
    clobber: bool,
    /// Print nothing but errors
    #[arg(short, long)]
    quiet: bool,
    /// Do not color the summary
    #[arg(short = 'K', long)]
    no_color: bool,
    /// How many times its size compressed evidence may expand to before a task stops
    /// (a guard against decompression bombs); 0 for no limit
    #[arg(long, value_name = "RATIO", default_value_t = nixcavate_source::DEFAULT_EXPANSION_LIMIT)]
    max_expansion: u64,
    /// Zone database used when the evidence names the host zone but lacks its data
    #[arg(long, value_name = "DIR", default_value = "/usr/share/zoneinfo")]
    zoneinfo: PathBuf,
}

#[derive(Args)]
struct AutoParseArgs {
    /// Evidence directory: a collection, a mounted volume, or a folder of collections and archives
    #[arg(short, long, value_name = "DIR", required_unless_present = "file", conflicts_with = "file")]
    directory: Option<PathBuf>,
    /// Evidence archive (.tar, .tar.gz, .tar.zst, .tar.xz, .zip)
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,
    /// Output directory
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,
    /// Run only these artifacts (comma-separated ids; see `nixcavate list`)
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    only: Vec<String>,
    /// Skip these artifacts
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    skip: Vec<String>,
    #[command(flatten)]
    common: Common,
}

#[derive(Args)]
struct ParseArgs {
    /// Artifact id (see `nixcavate list`)
    artifact: String,
    /// One file to parse, whatever its name
    #[arg(short, long, value_name = "FILE", required_unless_present = "directory", conflicts_with = "directory")]
    file: Option<PathBuf>,
    /// Directory or archive to search for this artifact
    #[arg(short, long, value_name = "DIR")]
    directory: Option<PathBuf>,
    /// Output file with -f [default: stdout]; output directory with -d (required)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    #[command(flatten)]
    common: Common,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::AutoParse(args) => {
            let evidence = args.directory.or(args.file).expect("clap requires one of -d and -f");
            auto_parse::run(&auto_parse::Options {
                evidence,
                output: args.output,
                only: args.only,
                skip: args.skip,
                common: args.common,
            })
        }
        Command::Parse(args) => auto_parse::run_parse(args),
        Command::SuperTimeline(args) => timeline::run(&args),
        Command::PersistenceHunter(args) => hunt::run(args),
        Command::List(args) => list::run(&args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("nixcavate: {message}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

//! `persistence-hunter`: runs the persistence parsers over the evidence, applies the checks in
//! `hunt_checks` and a YAML allow/block profile, and writes one row per finding.

mod joins;

use crate::auto_parse::{parse_all, Options};
use crate::hunt_checks::{executable_text, text, Severity, CHECKS};
use crate::{Common, OutputType, EXIT_OK, EXIT_PARTIAL};
use clap::Args;
use joins::Joins;
use nixcavate_core::manifest::Status;
use nixcavate_core::row::csv_field;
use nixcavate_source::glob::wildcard;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};

#[derive(Args)]
pub struct HuntArgs {
    /// Evidence directory: a collection, a mounted volume, or a folder of collections and archives
    #[arg(short, long, value_name = "DIR", required_unless_present = "file", conflicts_with = "file")]
    directory: Option<PathBuf>,
    /// Evidence archive (.tar, .tar.gz, .tar.zst, .tar.xz, .zip)
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,
    /// Output file [default: stdout]; -C replaces an existing file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// YAML profile with `allow` and `block` entries
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,
    /// Leave out findings below this severity
    #[arg(long, value_enum, default_value = "info")]
    min_severity: Severity,
    /// Keep allowed findings in the output, with status `allowed`
    #[arg(long)]
    show_allowed: bool,
    #[command(flatten)]
    common: Common,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default, deserialize_with = "null_is_empty")]
    allow: Vec<Allow>,
    #[serde(default, deserialize_with = "null_is_empty")]
    block: Vec<Block>,
}

/// A key left empty in the YAML (`allow:`) means no entries.
fn null_is_empty<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// Every key present must match the finding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allow {
    check: Option<String>,
    host: Option<String>,
    path: Option<String>,
    contains: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    contains: String,
    title: Option<String>,
    technique: Option<String>,
}

fn load_profile(path: &Path) -> Result<Profile, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(Profile::default());
    }
    let profile: Profile = serde_saphyr::from_str(&content).map_err(|e| format!("profile {}: {e}", path.display()))?;
    for (n, allow) in profile.allow.iter().enumerate() {
        let selectors = [&allow.check, &allow.host, &allow.path, &allow.contains];
        if selectors.iter().all(|s| s.is_none()) {
            return Err(format!(
                "profile {}: allow entry {} needs one of check, host, path, contains",
                path.display(),
                n + 1
            ));
        }
        // An empty selector matches everything: it would silence every finding.
        if selectors.iter().any(|s| s.as_deref() == Some("")) {
            return Err(format!("profile {}: allow entry {} has an empty selector", path.display(), n + 1));
        }
    }
    if profile.block.iter().any(|b| b.contains.is_empty()) {
        return Err(format!("profile {}: a block entry has an empty `contains`", path.display()));
    }
    Ok(profile)
}

impl Allow {
    /// `contains` is looked for in the finding's detail and in what the record runs
    /// (`executable`), not in the whole record.
    fn matches(&self, finding: &Finding, executable: &str) -> bool {
        let glob = |pattern: &Option<String>, value: &str| {
            pattern.as_deref().is_none_or(|p| wildcard(p.as_bytes(), value.as_bytes()))
        };
        glob(&self.check, &finding.check)
            && glob(&self.host, &finding.host)
            && glob(&self.path, &finding.source_path)
            && self.contains.as_deref().is_none_or(|c| finding.detail.contains(c) || executable.contains(c))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum State {
    Finding,
    Blocked,
    Allowed,
}

/// One output row. Field order is the column order.
#[derive(Serialize)]
struct Finding {
    host: String,
    severity: Severity,
    check: String,
    technique: String,
    tactic: String,
    title: String,
    status: State,
    #[serde(serialize_with = "printable_cell")]
    detail: String,
    artifact: String,
    source_path: String,
    source_line: Option<u64>,
    source_offset: Option<u64>,
    evidence: String,
    reason: String,
    /// 0 for a finding about a unit that is enabled, 1 otherwise: breaks ties within a severity.
    #[serde(skip)]
    rank: u8,
}

/// The detail comes from the evidence and may carry terminal escape sequences: control
/// characters other than tab are shown escaped. (The evidence column is JSON, which escapes
/// them already.)
fn printable_cell<S: serde::Serializer>(text: &str, serializer: S) -> Result<S::Ok, S::Error> {
    let escaped: String = text
        .chars()
        .flat_map(|c| if c.is_control() && c != '\t' { c.escape_default().collect() } else { vec![c] })
        .collect();
    serializer.serialize_str(&escaped)
}

/// Every string value in a record, with the JSON escaping removed.
fn strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

const COLUMNS: [&str; 14] = [
    "host",
    "severity",
    "check",
    "technique",
    "tactic",
    "title",
    "status",
    "detail",
    "artifact",
    "source_path",
    "source_line",
    "source_offset",
    "evidence",
    "reason",
];

/// Everything the checks and the profile say about one parsed record.
fn evaluate(record: &Value, profile: &Profile, joins: &Joins) -> Vec<Finding> {
    let joined = joins.annotate(record);
    let record = joined.as_ref().unwrap_or(record);
    let artifact = text(record, "artifact");
    let hits: Vec<_> =
        CHECKS.iter().filter(|c| c.artifact == artifact).filter_map(|c| Some((c, (c.test)(record)?))).collect();
    if hits.is_empty() && profile.block.is_empty() {
        return Vec::new();
    }
    let evidence = record.to_string();
    let make = |check: &str, technique: &str, tactic: &str, severity, title: &str, status, detail: String| Finding {
        host: text(record, "host").to_string(),
        severity,
        check: check.to_string(),
        technique: technique.to_string(),
        tactic: tactic.to_string(),
        title: title.to_string(),
        status,
        detail,
        artifact: artifact.to_string(),
        source_path: text(record, "source_path").to_string(),
        source_line: record["source_line"].as_u64(),
        source_offset: record["source_offset"].as_u64(),
        evidence: evidence.clone(),
        reason: String::new(),
        rank: u8::from(record["joined"]["enablement"] != "enabled"),
    };
    // A generic and a "suspicious" variant of one technique can both match a record: keep the stronger.
    let mut out: Vec<Finding> = hits
        .iter()
        .filter(|(c, _)| !hits.iter().any(|(o, _)| o.technique == c.technique && o.severity > c.severity))
        .map(|(c, detail)| make(c.id, c.technique, c.tactic, c.severity, c.title, State::Finding, detail.clone()))
        .collect();
    let mut values = Vec::new();
    if !profile.block.is_empty() {
        strings(record, &mut values);
    }
    for rule in profile.block.iter().filter(|b| values.iter().any(|v| v.contains(&b.contains))) {
        let title = rule.title.as_deref().unwrap_or("Matches a block rule");
        let technique = rule.technique.as_deref().unwrap_or("");
        let detail = format!("record contains `{}`", rule.contains);
        out.push(make("block-rule", technique, "", Severity::High, title, State::Blocked, detail));
    }
    let executable = executable_text(record);
    for finding in &mut out {
        if let Some(allow) = profile.allow.iter().find(|a| a.matches(finding, &executable)) {
            finding.status = State::Allowed;
            finding.reason = allow.reason.clone().unwrap_or_default();
        }
    }
    out
}

pub fn run(args: HuntArgs) -> Result<u8, String> {
    let evidence = args.directory.or(args.file).expect("clap requires one of -d and -f");
    if args.output.as_ref().is_some_and(|o| o.exists()) && !args.common.clobber {
        return Err(format!("{} exists; pass -C to replace it", args.output.unwrap_or_default().display()));
    }
    let profile = args.profile.as_deref().map(load_profile).transpose()?.unwrap_or_default();
    let (format, quiet) = (args.common.output_type, args.common.quiet);

    let mut only: Vec<String> = CHECKS.iter().map(|c| c.artifact.to_string()).collect();
    only.sort();
    only.dedup();
    let scratch = crate::auto_parse::private_temp_dir("nixcavate-hunt")
        .map_err(|e| format!("cannot create a scratch directory: {e}"))?;
    let common = Common { output_type: OutputType::Jsonl, clobber: true, quiet: true, ..args.common };
    let collected = parse_all(&Options { evidence, output: scratch.clone(), only, skip: vec![], common })
        .and_then(|manifest| Ok((read_findings(&manifest.tasks, &scratch, &profile)?, manifest.tasks)));
    let _ = fs::remove_dir_all(&scratch);
    let (mut findings, tasks) = collected?;

    findings.retain(|f| f.severity >= args.min_severity && (args.show_allowed || f.status != State::Allowed));
    findings.sort_by(|a, b| {
        let key = |f: &Finding| (f.source_line, f.source_offset);
        (&a.host, Reverse(a.severity), a.rank, &a.check, &a.source_path, key(a)).cmp(&(
            &b.host,
            Reverse(b.severity),
            b.rank,
            &b.check,
            &b.source_path,
            key(b),
        ))
    });
    let bytes = render(&findings, format)?;
    match &args.output {
        Some(path) => fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))?,
        None => std::io::stdout().lock().write_all(&bytes).map_err(|e| e.to_string())?,
    }
    if !quiet {
        print_summary(&findings);
    }
    let failed: Vec<_> = tasks.iter().filter(|t| t.status == Status::Failed).collect();
    for task in &failed {
        eprintln!(
            "failed: {} {}: {}",
            task.artifact,
            crate::report::printable(&task.input),
            crate::report::printable(task.error.as_deref().unwrap_or("unknown error"))
        );
    }
    Ok(if failed.is_empty() { EXIT_OK } else { EXIT_PARTIAL })
}

/// The artifacts the first pass reads.
const JOINED: [&str; 3] = ["systemd-enablement", "systemd-units", "passwd"];

/// Reads the JSONL each parser task wrote and evaluates every record.
fn read_findings(
    tasks: &[nixcavate_core::manifest::TaskEntry],
    scratch: &Path,
    profile: &Profile,
) -> Result<Vec<Finding>, String> {
    // First pass: the facts one record needs from another (enablement links, timers, accounts).
    let mut joins = Joins::default();
    let joined: Vec<_> =
        tasks.iter().filter(|t| JOINED.contains(&t.artifact.as_str())).flat_map(|t| &t.outputs).collect();
    for output in joined {
        let path = scratch.join(output);
        let content = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for line in content.lines().filter(|l| !l.is_empty()) {
            let record: Value = serde_json::from_str(line).map_err(|e| format!("{}: {e}", path.display()))?;
            joins.collect(&record);
        }
    }
    let mut findings = Vec::new();
    for output in tasks.iter().flat_map(|t| &t.outputs) {
        let path = scratch.join(output);
        let content = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for line in content.lines().filter(|l| !l.is_empty()) {
            let record: Value = serde_json::from_str(line).map_err(|e| format!("{}: {e}", path.display()))?;
            findings.extend(evaluate(&record, profile, &joins));
        }
    }
    Ok(findings)
}

fn render(findings: &[Finding], format: OutputType) -> Result<Vec<u8>, String> {
    let json = |e: serde_json::Error| e.to_string();
    let mut out = Vec::new();
    match format {
        OutputType::Json => {
            out = serde_json::to_vec(findings).map_err(json)?;
            out.push(b'\n');
        }
        OutputType::Jsonl => {
            for finding in findings {
                serde_json::to_writer(&mut out, finding).map_err(json)?;
                out.push(b'\n');
            }
        }
        OutputType::Csv => {
            out.extend_from_slice(COLUMNS.join(",").as_bytes());
            out.push(b'\n');
            for finding in findings {
                let row = serde_json::to_value(finding).map_err(json)?;
                for (i, column) in COLUMNS.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    match &row[column] {
                        Value::String(s) => csv_field(&mut out, s.as_bytes()),
                        Value::Null => {}
                        other => out.extend_from_slice(other.to_string().as_bytes()),
                    }
                }
                out.push(b'\n');
            }
        }
    }
    Ok(out)
}

fn print_summary(findings: &[Finding]) {
    let open: Vec<_> = findings.iter().filter(|f| f.status != State::Allowed).collect();
    let count = |severity| open.iter().filter(|f| f.severity == severity).count();
    let mut checks: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in &open {
        *checks.entry(&finding.check).or_default() += 1;
    }
    let mut top: Vec<_> = checks.into_iter().collect();
    top.sort_by_key(|&(check, n)| (Reverse(n), check));
    let top: Vec<String> = top.iter().take(5).map(|(check, n)| format!("{check} x{n}")).collect();
    eprintln!(
        "persistence-hunter: {} findings ({} high, {} medium, {} low, {} info), {} allowed",
        open.len(),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info),
        findings.len() - open.len()
    );
    if !top.is_empty() {
        eprintln!("  top checks: {}", top.join(", "));
    }
}

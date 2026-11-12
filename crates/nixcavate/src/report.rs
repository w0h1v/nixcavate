//! The terminal summary of a run.

use nixcavate_core::manifest::{Manifest, Status, TaskEntry, MANIFEST_NAME};
use std::borrow::Cow;
use std::io::IsTerminal;
use std::path::Path;

pub fn print_summary(manifest: &Manifest, output: &Path, color: bool) {
    let color = color && std::io::stdout().is_terminal();
    let paint = |code: &str, text: &str| if color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() };
    let count = |status: Status| manifest.tasks.iter().filter(|t| t.status == status).count();
    let sum = |f: fn(&TaskEntry) -> u64| manifest.tasks.iter().map(f).sum::<u64>();
    let (failed, seconds) = (count(Status::Failed), manifest.duration_ms as f64 / 1000.0);
    let input = sum(|t| t.input_bytes);

    println!("{}", paint("1", &format!("nixcavate {} auto-parse", manifest.tool_version)));
    for host in &manifest.hosts {
        println!(
            "  host     {} ({}, {}), zone: {}",
            paint("1", &printable(&host.name)),
            host.os,
            printable(or_unknown(&host.os_version)),
            printable(&host.timezone)
        );
    }
    if manifest.hosts.is_empty() {
        println!("  no hosts found in the evidence");
    }
    let failed_text = format!("{failed} failed");
    println!(
        "  tasks    {} succeeded, {} skipped, {}",
        count(Status::Succeeded),
        count(Status::Skipped),
        if failed > 0 { paint("31", &failed_text) } else { failed_text }
    );
    println!("  output   {} records, {} timeline events", group(sum(|t| t.records)), group(sum(|t| t.events)));
    println!(
        "  input    {} in {seconds:.2} s on {} threads ({}/s)",
        bytes(input),
        manifest.threads,
        bytes((input as f64 / seconds.max(1e-3)) as u64)
    );

    let mut slowest: Vec<&TaskEntry> = manifest.tasks.iter().filter(|t| t.duration_ms > 0).collect();
    slowest.sort_by_key(|t| std::cmp::Reverse(t.duration_ms));
    if !slowest.is_empty() {
        println!("  slowest tasks");
        for task in slowest.iter().take(5) {
            println!(
                "    {:>7} ms  {:<16} {} ({})",
                task.duration_ms,
                task.artifact,
                printable(&task.input),
                bytes(task.input_bytes)
            );
        }
    }
    if failed > 0 {
        println!("  {}", paint("31", "failed tasks"));
        for task in manifest.tasks.iter().filter(|t| t.status == Status::Failed) {
            let error = task.error.as_deref().unwrap_or("unknown error");
            println!("    {:<16} {}: {}", task.artifact, printable(&task.input), printable(error));
            println!("    {:<16} {}", "", coverage(task));
        }
    }
    // A skipped input that is not empty holds data nixcavate could not read (bzip2, an
    // unsupported variant). Its last-written time says whether that matters.
    let unread: Vec<&TaskEntry> =
        manifest.tasks.iter().filter(|t| t.status == Status::Skipped && t.input_bytes > 0).collect();
    if !unread.is_empty() {
        println!("  skipped inputs that hold data");
        for task in unread.iter().take(10) {
            let why = task.error.as_deref().unwrap_or("skipped");
            let written = task.input_modified.as_deref().unwrap_or("unknown");
            println!(
                "    {:<16} {}: {} (last written {written})",
                task.artifact,
                printable(&task.input),
                printable(why)
            );
        }
        if unread.len() > 10 {
            println!("    ... and {} more; see the manifest", unread.len() - 10);
        }
    }
    println!("  manifest {}", output.join(MANIFEST_NAME).display());
}

/// Text from the evidence, made safe to print: host names, paths and messages are
/// attacker-controlled and could carry terminal escape sequences.
pub fn printable(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        Cow::Owned(
            text.chars()
                .flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

/// What a task that did not finish is known to cover, so an analyst can tell whether the
/// part that was not parsed matters for the period under investigation.
pub fn coverage(task: &TaskEntry) -> String {
    let written = task.input_modified.as_deref().map_or("an unknown time".to_string(), |t| t.to_string());
    match (&task.first_event, &task.last_event) {
        (Some(first), Some(last)) => format!("parsed {first} to {last}; the file was last written {written}"),
        _ => format!("nothing parsed; the file was last written {written}"),
    }
}

fn or_unknown(text: &str) -> &str {
    if text.is_empty() {
        "version unknown"
    } else {
        text
    }
}

/// `1234567` as `1,234,567`.
fn group(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_numbers() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1_234_567), "1,234,567");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(3 << 30), "3.0 GiB");
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(printable("web01"), "web01");
        assert_eq!(printable("\u{1b}]0;title\u{7}evil\n"), "\\u{1b}]0;title\\u{7}evil\\n");
    }
}

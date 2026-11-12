//! `/var/log/apt/history.log`: one block per apt transaction. The format is apt's own
//! (deb822-like `Key: value` lines, blocks separated by blank lines), documented in apt(8) logging.

use super::dpkg::wall_secs;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "apt-history",
    "APT install, upgrade and removal transactions",
    Category::Software,
    LINUX,
    &["var/log/apt/history.log*"],
    parse,
);

#[derive(Serialize, Default)]
struct Transaction {
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    command: String,
    requested_by: String,
    requested_by_uid: Option<u32>,
    /// Items are `pkg:arch version`, with ` (automatic)` for packages pulled in as dependencies.
    installed: Vec<String>,
    /// Items are `pkg:arch old -> new`.
    upgraded: Vec<String>,
    removed: Vec<String>,
    purged: Vec<String>,
    reinstalled: Vec<String>,
    downgraded: Vec<String>,
    error: String,
}

impl Record for Transaction {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let counts: Vec<String> = [
            ("installed", &self.installed),
            ("upgraded", &self.upgraded),
            ("removed", &self.removed),
            ("purged", &self.purged),
            ("reinstalled", &self.reinstalled),
            ("downgraded", &self.downgraded),
        ]
        .iter()
        .filter(|(_, items)| !items.is_empty())
        .map(|(what, items)| format!("{} {what}", items.len()))
        .collect();
        let command = if self.command.is_empty() { "apt transaction" } else { &self.command };
        let message =
            if counts.is_empty() { command.to_string() } else { format!("{command} ({})", counts.join(", ")) };
        self.time.map(|time| Event::new(time, "apt_transaction", message)).into_iter()
    }
}

/// Parses `pkg:arch (a, b), pkg2:arch (c)` into `pkg:arch a` / `pkg:arch a -> b` items.
/// Version strings never contain parentheses, so `)` ends each item.
fn package_list(value: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut rest = value;
    while let Some((name, tail)) = rest.split_once(" (") {
        let (inside, after) = tail.split_once(')').unwrap_or((tail, ""));
        let mut parts = inside.split(", ");
        let first = parts.next().unwrap_or("");
        items.push(match parts.next() {
            Some("automatic") => format!("{} {first} (automatic)", name.trim()),
            Some(new) => format!("{} {first} -> {new}", name.trim()),
            None => format!("{} {first}", name.trim()),
        });
        rest = after.trim_start_matches(", ");
    }
    items
}

/// Splits `alice (1000)` into the name and the uid.
fn requester(value: &str) -> (&str, Option<u32>) {
    match value.rsplit_once(" (") {
        Some((name, uid)) => (name, uid.trim_end_matches(')').parse().ok()),
        None => (value, None),
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut block: Option<(u64, Transaction)> = None;
    let finish = |sink: &mut Sink, block: Option<(u64, Transaction)>| -> Result<()> {
        let Some((at, transaction)) = block else { return Ok(()) };
        if transaction.time.is_none() {
            sink.warn(format!("line {at}: block has no valid Start-Date"));
        }
        sink.emit(Loc::Line(at), &transaction)
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return finish(sink, block.take());
        }
        let Some((key, value)) = text.split_once(':') else {
            sink.warn(format!("line {}: not a `Key: value` line", line.number));
            return Ok(());
        };
        let value = value.trim();
        // A second `Start-Date` with no blank line before it starts a new transaction.
        if key == "Start-Date" && block.as_ref().is_some_and(|(_, t)| t.time.is_some()) {
            finish(sink, block.take())?;
        }
        let (_, t) = block.get_or_insert_with(|| (line.number, Transaction::default()));
        let wall = |value: &str| {
            let mut parts = value.split_ascii_whitespace();
            let secs = wall_secs(parts.next()?.as_bytes(), parts.next()?.as_bytes())?;
            Some(input.local_time(secs, 0, Precision::Seconds))
        };
        match key {
            "Start-Date" => t.time = wall(value),
            "End-Date" => t.end_time = wall(value),
            "Commandline" => t.command = value.to_string(),
            "Requested-By" => {
                let (name, uid) = requester(value);
                (t.requested_by, t.requested_by_uid) = (name.to_string(), uid);
            }
            "Install" => t.installed = package_list(value),
            "Upgrade" => t.upgraded = package_list(value),
            "Remove" => t.removed = package_list(value),
            "Purge" => t.purged = package_list(value),
            "Reinstall" => t.reinstalled = package_list(value),
            "Downgrade" => t.downgraded = package_list(value),
            "Error" => t.error = value.to_string(),
            _ => {}
        }
        Ok(())
    })?;
    finish(sink, block.take())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    #[test]
    fn real_history() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/apt/history.log", &fixture("apt-history/history.log"), 0));
    }

    #[test]
    fn upgrades_errors_and_malformed_blocks() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/apt/history.log", &fixture("apt-history/extra.log"), 0));
    }

    #[test]
    fn rotated_history_is_decompressed() {
        let plain = fixture("apt-history/history.log");
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&plain).unwrap();
        let rotated = run(&ARTIFACT, "var/log/apt/history.log.1.gz", &gz.finish().unwrap(), 0);
        assert_eq!(
            rotated.replace("history.log.1.gz", "history.log"),
            run(&ARTIFACT, "var/log/apt/history.log", &plain, 0)
        );
    }

    #[test]
    fn start_date_without_a_blank_line_starts_a_new_transaction() {
        let data = b"Start-Date: 2024-03-10  01:02:03\nCommandline: apt a\nStart-Date: 2024-03-11  01:02:03\nCommandline: apt b\n";
        let out = run(&ARTIFACT, "var/log/apt/history.log", data, 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 2, "{out}");
        assert!(out.contains("\"command\":\"apt a\"") && out.contains("\"command\":\"apt b\""), "{out}");
    }

    #[test]
    fn empty_file() {
        assert_eq!(run(&ARTIFACT, "var/log/apt/history.log", b"", 0), "");
    }

    #[test]
    fn start_date_uses_the_host_zone() {
        let files: &[(&str, &[u8])] = &[
            ("var/log/apt/history.log", b"Start-Date: 2024-03-10  01:02:03\nCommandline: apt update\n"),
            ("etc/localtime", &fixture("dpkg-log/Europe_Berlin.tzif")),
        ];
        let out = run_on_host(&ARTIFACT, files, "var/log/apt/history.log", 0);
        assert!(out.contains("2024-03-10T00:02:03Z"), "{out}");
    }

    #[test]
    fn never_panics_on_damaged_input() {
        let data = fixture("apt-history/history.log");
        for len in (0..data.len()).step_by(11) {
            run(&ARTIFACT, "var/log/apt/history.log", &data[..len], 0);
        }
        let mut seed = 99u64;
        for _ in 0..200 {
            let mut copy = data.clone();
            for _ in 0..8 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed >> 33) as usize % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&ARTIFACT, "var/log/apt/history.log", &copy, 0);
        }
    }
}

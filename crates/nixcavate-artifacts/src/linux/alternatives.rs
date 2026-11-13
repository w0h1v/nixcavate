//! `/var/log/alternatives.log`: what `update-alternatives` (Debian's `dpkg` tools) was asked to
//! do and what it changed. Lines are `update-alternatives YYYY-MM-DD HH:MM:SS: run with
//! <options>` or `...: link group <name> updated to point to <path>`. The time is host-local
//! with no zone. An alternative decides which program runs under a generic name (`editor`,
//! `java`), so a changed link is a way to substitute a program.

use super::dpkg::wall_secs;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "alternatives-log",
    "update-alternatives actions",
    Category::Software,
    LINUX,
    &["var/log/alternatives.log*"],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Timestamp,
    /// `install`, `set`, `remove`, `remove-all`, `auto`, `config`, `link_updated`, or `message`.
    action: &'a str,
    /// The alternative's name (`editor`).
    name: &'a str,
    /// The program path the action names or points the link at.
    path: &'a str,
    /// The options of a `run with` line, or the text of any other line.
    detail: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = match self.action {
            "install" | "set" | "remove" | "remove-all" | "auto" | "link_updated" => {
                format!("alternative {} {} {}", self.name, self.action, self.path).trim_end().to_string()
            }
            _ => return None.into_iter(),
        };
        Some(Event::new(self.time, "alternative_changed", message)).into_iter()
    }
}

/// `--install <link> <name> <path> <priority> ...`, `--set <name> <path>`, `--remove <name> <path>`,
/// `--auto <name>`, `--remove-all <name>`, `--config <name>`.
fn run_options(options: &str) -> (&'static str, &str, &str) {
    let mut words = options.split_ascii_whitespace();
    let Some(first) = words.next() else { return ("message", "", "") };
    let mut word = || words.next().unwrap_or("");
    match first {
        "--install" => {
            let _link = word();
            ("install", word(), word())
        }
        "--set" => ("set", word(), word()),
        "--remove" => ("remove", word(), word()),
        "--remove-all" => ("remove-all", word(), ""),
        "--auto" => ("auto", word(), ""),
        "--config" => ("config", word(), ""),
        _ => ("message", "", ""),
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut last = (i64::MIN, input.local_time(0, 0, Precision::Seconds));
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let text = lossy(line.bytes);
        let parsed = text.strip_prefix("update-alternatives ").and_then(|rest| {
            let (date, rest) = rest.split_once(' ')?;
            let (time, rest) = rest.split_once(": ")?;
            Some((wall_secs(date.as_bytes(), time.as_bytes())?, rest))
        });
        let Some((secs, rest)) = parsed else {
            sink.warn(format!("offset {}: not an alternatives.log line", line.offset));
            return Ok(());
        };
        if last.0 != secs {
            last = (secs, input.local_time(secs, 0, Precision::Seconds));
        }
        let mut entry = Entry { time: last.1, action: "message", name: "", path: "", detail: rest };
        if let Some(options) = rest.strip_prefix("run with ") {
            (entry.action, entry.name, entry.path) = run_options(options);
            entry.detail = options;
        } else if let Some(update) = rest.strip_prefix("link group ") {
            // `editor updated to point to /bin/nano`
            if let Some((name, path)) = update.split_once(" updated to point to ") {
                (entry.action, entry.name, entry.path) = ("link_updated", name, path);
                entry.detail = "";
            }
        }
        sink.emit(Loc::Offset(line.offset), &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_a_real_log() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "var/log/alternatives.log",
            &fixture("alternatives-log/alternatives.log"),
            0
        ));
    }

    #[test]
    fn other_options_and_bad_lines() {
        let log = concat!(
            "update-alternatives 2024-03-10 01:02:03: run with --auto editor\n",
            "update-alternatives 2024-03-10 01:02:04: run with --remove-all java\n",
            "update-alternatives 2024-03-10 01:02:05: run with --config pager\n",
            "update-alternatives 2024-03-10 01:02:06: run with --weird x\n",
            "update-alternatives 2024-03-10 01:02:07: link /usr/bin/foo is dangling\n",
            "update-alternatives 2024-03-10 01:02:08: run with\n",
            "update-alternatives not-a-date 01:02:03: run with --auto x\n",
            "garbage\n",
        );
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/alternatives.log", log.as_bytes(), 0));
    }

    #[test]
    fn empty_log_produces_nothing() {
        assert_eq!(run(&ARTIFACT, "var/log/alternatives.log", b"", 0), "");
    }
}

//! SUSE package history: `/var/log/zypp/history`, written by libzypp for zypper, YaST and
//! the packagekit/zypp stack. One `|`-separated line per event:
//!
//! ```text
//! 2024-03-10 01:02:03|install|name|version|arch|user@host|repo|checksum|
//! 2024-03-10 01:02:04|remove |name|version|arch|user@host|
//! 2024-03-10 01:02:03|command|user@host|'zypper' 'in' 'x'|
//! 2024-03-10 01:02:03|radd|alias|url|        (also `rremove|alias|`)
//! 2024-03-10 01:02:03|patch |id|revision|arch|repo|severity|category|...|
//! ```
//!
//! The format is libzypp's own `HistoryLog`; the fields above were checked against the logs
//! of openSUSE Leap 15.6, Tumbleweed and SLES 15/16. Lines starting with `#` are libzypp's
//! comments (per-package success lines and rpm script output) and are skipped. Times are
//! host-local with no zone.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const HISTORY: Artifact = Artifact::new(
    "zypp-history",
    "SUSE zypper installs, removals and commands",
    Category::Software,
    LINUX,
    &["var/log/zypp/history*"],
    parse,
)
.split_lines();

/// More fields than any action has; the rest of a longer line is dropped.
const MAX_FIELDS: usize = 16;

#[derive(Serialize)]
struct Entry<'a> {
    time: Timestamp,
    /// `install`, `remove`, `command`, `radd`, `rremove`, `patch`, or whatever else libzypp writes.
    action: &'a str,
    /// A package name, a patch id or a repository alias, by action.
    package: &'a str,
    version: &'a str,
    architecture: &'a str,
    /// `user@host` that ran the command or the transaction.
    user: &'a str,
    repository: &'a str,
    /// The package checksum libzypp recorded (hex SHA-256 or SHA-1).
    checksum: &'a str,
    /// The zypper command line, for `command`; the URL, for `radd`.
    command: &'a str,
    /// The fields of a `patch` line after the repository: severity, category, status.
    detail: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let event = match self.action {
            "install" => {
                let mut message = format!("installed {} {}", self.package, self.version);
                if !self.repository.is_empty() {
                    message.push_str(&format!(" from {}", self.repository));
                }
                Event::new(self.time, "package_installed", message)
            }
            "remove" => Event::new(self.time, "package_removed", format!("removed {} {}", self.package, self.version)),
            "command" => Event::new(self.time, "package_command", self.command),
            "radd" => Event::new(self.time, "repository_added", format!("{} {}", self.package, self.command)),
            "rremove" => Event::new(self.time, "repository_removed", self.package),
            _ => return None.into_iter(),
        };
        Some(event).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut last = (i64::MIN, input.local_time(0, 0, Precision::Seconds));
    for_each_line(input, |line| {
        let bytes = line.bytes;
        if bytes.iter().all(u8::is_ascii_whitespace) || bytes.starts_with(b"#") {
            return Ok(());
        }
        let text = lossy(bytes);
        let mut fields = [""; MAX_FIELDS];
        let mut count = 0;
        for field in text.split('|').take(MAX_FIELDS) {
            fields[count] = field;
            count += 1;
        }
        // The whole first field is the time.
        let time = parse_iso8601(fields[0].as_bytes()).filter(|(_, used)| *used == fields[0].len() && count > 2);
        let time = time.map(|(parsed, _)| parsed);
        let Some(time) = time else {
            sink.warn(format!("offset {}: not a zypp history line", line.offset));
            return Ok(());
        };
        let when = match time.recorded() {
            Some(recorded) => recorded,
            None => {
                if last.0 != time.secs {
                    last = (time.secs, input.local_time(time.secs, 0, Precision::Seconds));
                }
                last.1
            }
        };
        let f = |n: usize| if n < count { fields[n] } else { "" };
        let action = f(1).trim();
        let mut entry = Entry {
            time: when,
            action,
            package: "",
            version: "",
            architecture: "",
            user: "",
            repository: "",
            checksum: "",
            command: "",
            detail: "",
        };
        match action {
            "command" => (entry.user, entry.command) = (f(2), f(3)),
            "install" | "remove" => {
                (entry.package, entry.version, entry.architecture, entry.user) = (f(2), f(3), f(4), f(5));
                (entry.repository, entry.checksum) = (f(6), f(7));
            }
            "radd" => (entry.package, entry.command) = (f(2), f(3)),
            "rremove" => entry.package = f(2),
            "patch" => {
                (entry.package, entry.version, entry.architecture, entry.repository) = (f(2), f(3), f(4), f(5));
                // The rest of the line, from the sixth field on.
                entry.detail = nth_field_tail(&text, 6).trim_end_matches('|');
            }
            _ => entry.detail = nth_field_tail(&text, 2).trim_end_matches('|'),
        }
        sink.emit(Loc::Offset(line.offset), &entry)
    })
}

/// The text from field `n` (0-based) to the end of the line.
fn nth_field_tail(text: &str, n: usize) -> &str {
    let mut rest = text;
    for _ in 0..n {
        match rest.split_once('|') {
            Some((_, tail)) => rest = tail,
            None => return "",
        }
    }
    rest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_a_real_history() {
        insta::assert_snapshot!(run(&HISTORY, "var/log/zypp/history", &fixture("zypp-history/history"), 0));
    }

    #[test]
    fn repositories_unknown_actions_and_bad_lines() {
        let log = concat!(
            "# 2024-03-10 01:02:03 foo-1.rpm installed ok\n",
            "2024-03-10 01:02:03|radd|evil|https://example.invalid/repo|\n",
            "2024-03-10 01:02:04|rremove|evil|\n",
            "2024-03-10 01:02:05|rename|a|b|c|\n",
            "2024-03-10 01:02:06|install|short\n",
            "not a time|install|x|1|noarch|u@h|r|c|\n",
            "2024-03-10 01:02:07\n",
            "2024-13-45 99:99:99|install|x|1|noarch|u@h|r|c|\n",
        );
        insta::assert_snapshot!(run(&HISTORY, "var/log/zypp/history", log.as_bytes(), 0));
    }

    #[test]
    fn empty_history_produces_nothing() {
        assert_eq!(run(&HISTORY, "var/log/zypp/history", b"", 0), "");
    }

    #[test]
    fn mutated_histories_never_panic() {
        let log = fixture("zypp-history/history");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for len in (0..log.len()).step_by(53) {
            let _ = run(&HISTORY, "var/log/zypp/history", &log[..len], 0);
        }
        for _ in 0..300 {
            let mut copy = log.clone();
            for _ in 0..1 + next() % 8 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = run(&HISTORY, "var/log/zypp/history", &copy, 0);
        }
    }
}

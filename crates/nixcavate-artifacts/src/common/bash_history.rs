//! `.bash_history`. Format: bash(1) "HISTORY"; with `HISTTIMEFORMAT` set, each command is
//! preceded by a `#<epoch>` comment line.

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "bash-history",
    "Bash command history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.bash_history",
        "root/.bash_history",
        "Users/*/.bash_history",
        "private/var/root/.bash_history",
        "var/root/.bash_history",
    ],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    user: &'a str,
    /// Present only when the shell had `HISTTIMEFORMAT` set while recording.
    time: Option<Timestamp>,
    command: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "executed", format!("{} ran {}", self.user, self.command))).into_iter()
    }
}

/// `#` plus 9 to 11 digits and nothing else; anything else starting with `#` is a command.
fn timestamp_line(line: &[u8]) -> Option<i64> {
    let digits = line.strip_prefix(b"#")?;
    if !(9..=11).contains(&digits.len()) {
        return None;
    }
    i64::try_from(parse_uint(digits)?).ok()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let mut pending = None;
    for_each_line(input, |line| {
        if let Some(secs) = timestamp_line(line.bytes) {
            pending = Some(Timestamp::from_secs(secs, Basis::Recorded));
            return Ok(());
        }
        if line.bytes.is_empty() {
            return Ok(());
        }
        let time = pending.take();
        sink.emit(Loc::Line(line.number), &Entry { user, time, command: &lossy(line.bytes) })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn timestamped_history_from_bash() {
        insta::assert_snapshot!(run(&ARTIFACT, "home/alice/.bash_history", &fixture("bash-history/.bash_history"), 0));
    }

    #[test]
    fn edge_cases() {
        let data = b"#1700000000\r\nls\r\n#12345678\r\n#999999999\r\n#170000000012\r\n#1700000001\r\n#1700000002\r\n";
        insta::assert_snapshot!(run(&ARTIFACT, "root/.bash_history", data, 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "root/.bash_history", b"", 0), "");
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "root/.bash_history", &garbage, 0);
    }
}

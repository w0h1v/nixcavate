//! Interactive-tool histories that carry no timestamps: `.python_history`, `.mysql_history`
//! and `.lesshst`. Formats: GNU readline / libedit history files (libedit's `_HiStOrY_V2_`
//! writes spaces and other characters as octal `\040`), and less(1) "HISTORY".

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;
use std::borrow::Cow;

pub const PYTHON: Artifact = Artifact::new(
    "python-history",
    "Python interactive history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.python_history",
        "root/.python_history",
        "Users/*/.python_history",
        "private/var/root/.python_history",
        "var/root/.python_history",
    ],
    parse_command_history,
);

pub const MYSQL: Artifact = Artifact::new(
    "mysql-history",
    "MySQL client history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.mysql_history",
        "root/.mysql_history",
        "Users/*/.mysql_history",
        "private/var/root/.mysql_history",
        "var/root/.mysql_history",
    ],
    parse_command_history,
);

pub const LESS: Artifact = Artifact::new(
    "less-history",
    "less search, shell and mark history",
    Category::Execution,
    ANY_OS,
    &["home/*/.lesshst", "root/.lesshst", "Users/*/.lesshst", "private/var/root/.lesshst", "var/root/.lesshst"],
    parse_less,
);

const LIBEDIT_HEADER: &[u8] = b"_HiStOrY_V2_";

#[derive(Serialize)]
struct Command<'a> {
    user: &'a str,
    command: &'a str,
}

impl Record for Command<'_> {}

/// Replaces `\ooo` (three octal digits) with that byte. Other backslashes stay as they are.
fn decode_octal(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.contains(&b'\\') {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let octal = match bytes.get(i + 1..i + 4) {
            Some(d) if b == b'\\' && d[0] <= b'3' && d.iter().all(|c| (b'0'..=b'7').contains(c)) => {
                Some((d[0] - b'0') << 6 | (d[1] - b'0') << 3 | (d[2] - b'0'))
            }
            _ => None,
        };
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }
    Cow::Owned(out)
}

/// One command per line. Files in libedit's V2 form (macOS Python, some MySQL clients) start
/// with a marker line and escape their text.
fn parse_command_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let mut escaped = false;
    for_each_line(input, |line| {
        if line.number == 1 && line.bytes == LIBEDIT_HEADER {
            escaped = true;
            return Ok(());
        }
        if line.bytes.is_empty() {
            return Ok(());
        }
        let decoded = if escaped { decode_octal(line.bytes) } else { Cow::Borrowed(line.bytes) };
        sink.emit(Loc::Line(line.number), &Command { user, command: &lossy(&decoded) })
    })
}

#[derive(Serialize)]
struct Item<'a> {
    user: &'a str,
    /// `search`, `shell` or `mark`.
    kind: &'static str,
    text: &'a str,
}

impl Record for Item<'_> {}

fn parse_less(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let mut section: &'static str = "";
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let (kind, text) = match (section, &*text) {
            (_, header) if header.starts_with('.') => {
                section = match header {
                    ".search" => "search",
                    ".shell" => "shell",
                    ".mark" => "mark",
                    _ => "",
                };
                return Ok(());
            }
            ("search" | "shell", entry) if entry.starts_with('"') => (section, &entry[1..]),
            ("mark", entry) if entry.starts_with("m ") => (section, &entry[2..]),
            _ => return Ok(()),
        };
        sink.emit(Loc::Line(line.number), &Item { user, kind, text })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn python_history() {
        let data = fixture("python-history/.python_history");
        insta::assert_snapshot!(run(&PYTHON, "home/alice/.python_history", &data, 0));
    }

    #[test]
    fn mysql_history_v2_is_decoded() {
        let data = fixture("mysql-history/.mysql_history");
        insta::assert_snapshot!(run(&MYSQL, "root/.mysql_history", &data, 0));
    }

    #[test]
    fn mysql_history_plain_and_crlf() {
        insta::assert_snapshot!(run(&MYSQL, "home/bob/.mysql_history", b"select 1;\r\nshow\\040tables;\r\n\r\n", 0));
        // Octal escapes are only meaningful after the V2 marker; the last one is not octal.
        let v2 = b"_HiStOrY_V2_\nselect\\040\\134\\18\\777;\n";
        insta::assert_snapshot!(run(&MYSQL, "home/bob/.mysql_history", v2, 0));
    }

    #[test]
    fn less_history() {
        let data = fixture("less-history/.lesshst");
        insta::assert_snapshot!(run(&LESS, "Users/sam/.lesshst", &data, 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        for artifact in [&PYTHON, &MYSQL, &LESS] {
            assert_eq!(run(artifact, "root/.x", b"", 0), "");
            run(artifact, "root/.x", &garbage, 0);
            run(artifact, "root/.x", b"_HiStOrY_V2_\n\\", 0);
        }
    }
}

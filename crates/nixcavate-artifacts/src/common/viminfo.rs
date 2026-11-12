//! `.viminfo`. Format: Vim's `:help viminfo-file-marks` and `:help viminfo`. Each history item
//! and mark is written as a plain line and, from viminfo version 4, repeated as a `|` bar
//! line that adds the epoch time: `|2,<type>,<time>,,"text"` for history (type 0 command,
//! 1 search) and `|4,<mark>,<line>,<col>,<time>,"path"` for marks. Neovim's `shada` is a
//! different format and is not read.

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "viminfo",
    "Vim command, search and file history",
    Category::Execution,
    ANY_OS,
    &["home/*/.viminfo", "root/.viminfo", "Users/*/.viminfo", "private/var/root/.viminfo", "var/root/.viminfo"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    user: &'a str,
    /// `command`, `search` or `file_mark`.
    kind: &'static str,
    time: Option<Timestamp>,
    text: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, verb) = match self.kind {
            "command" => ("executed", "ran vim command"),
            "file_mark" => ("file_opened", "opened in vim"),
            _ => return None.into_iter(),
        };
        self.time.map(|ts| Event::new(ts, kind, format!("{} {verb}: {}", self.user, self.text))).into_iter()
    }
}

/// An item seen as a plain line, waiting for the bar line that may follow with its time.
struct Pending {
    line: u64,
    kind: &'static str,
    text: String,
}

/// Unquotes a bar-line string: `"..."` with `\\`, `\"` and `\n` escapes.
fn bar_string(field: &str) -> String {
    let inner = field.strip_prefix('"').unwrap_or(field);
    let inner = inner.strip_suffix('"').unwrap_or(inner);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some('n')) => out.push('\n'),
            ('\\', Some(escaped @ ('\\' | '"'))) => out.push(escaped),
            _ => {
                out.push(c);
                continue;
            }
        }
        chars.next();
    }
    out
}

/// The path of a plain mark line, after the mark name, line and column.
fn mark_path(text: &str) -> Option<&str> {
    if !(text.starts_with('\'') || text.starts_with("-'")) {
        return None;
    }
    let mut rest = text;
    for _ in 0..3 {
        rest = rest[rest.find([' ', '\t'])?..].trim_start();
    }
    Some(rest)
}

fn time_of(field: &str) -> Option<Timestamp> {
    let secs = i64::try_from(parse_uint(field.as_bytes())?).ok().filter(|&s| s > 0)?;
    Some(Timestamp::from_secs(secs, Basis::Recorded))
}

/// A bar line as `(kind, time, text)`; only history (`|2`) and marks (`|4`) are of interest.
fn bar_item(rest: &str) -> Option<(&'static str, Option<Timestamp>, String)> {
    let (number, rest) = rest.split_once(',')?;
    let mut fields = rest.splitn(5, ',');
    match number {
        "2" => {
            let kind = match fields.next()? {
                "0" => "command",
                "1" => "search",
                _ => return None,
            };
            let time = time_of(fields.next()?);
            Some((kind, time, bar_string(fields.nth(1)?)))
        }
        "4" => {
            let time = time_of(fields.nth(3)?);
            Some(("file_mark", time, bar_string(fields.next()?)))
        }
        _ => None,
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let (mut marks_section, mut file_history) = (false, false);
    let mut pending: Option<Pending> = None;
    let emit = |sink: &mut Sink, line: u64, kind: &'static str, time: Option<Timestamp>, text: &str| {
        sink.emit(Loc::Line(line), &Entry { user, kind, time, text })
    };

    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if let Some(rest) = text.strip_prefix('|') {
            let item = bar_item(rest);
            match (pending.take(), item) {
                // The plain line is the authoritative text; the bar line adds the time.
                (Some(p), Some((_, time, _))) => emit(sink, p.line, p.kind, time, &p.text)?,
                (Some(p), None) => emit(sink, p.line, p.kind, None, &p.text)?,
                (None, Some((kind, time, text))) => emit(sink, line.number, kind, time, &text)?,
                (None, None) => {}
            }
            return Ok(());
        }
        if let Some(p) = pending.take() {
            emit(sink, p.line, p.kind, None, &p.text)?;
        }
        if text.starts_with('#') {
            marks_section = text.starts_with("# File marks") || text.starts_with("# Jumplist");
            // `> /path` heads the marks kept for each file Vim has edited.
            file_history = text.starts_with("# History of marks within files");
            return Ok(());
        }
        let item = if let Some(command) = text.strip_prefix(':') {
            Some(("command", command))
        } else if let Some(pattern) = text.strip_prefix("? ").or_else(|| text.strip_prefix("/ ")) {
            Some(("search", pattern))
        } else if file_history {
            text.strip_prefix("> ").map(|path| ("file_mark", path))
        } else if marks_section {
            // `'0  <line>  <col>  <path>` or `-'  <line>  <col>  <path>`
            mark_path(&text).map(|path| ("file_mark", path))
        } else {
            None
        };
        pending = item.map(|(kind, text)| Pending { line: line.number, kind, text: text.to_string() });
        Ok(())
    })?;
    match pending {
        Some(p) => emit(sink, p.line, p.kind, None, &p.text),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn viminfo_from_vim() {
        insta::assert_snapshot!(run(&ARTIFACT, "home/alice/.viminfo", &fixture("viminfo/.viminfo"), 0));
    }

    #[test]
    fn old_format_without_bar_lines_and_crlf() {
        let data = b"# Command Line History (newest to oldest):\r\n:wq\r\n\r\n# Search String History (newest to oldest):\r\n/ foo\r\n\r\n\
                     # File marks:\r\n'0  3  7  /srv/a b.txt\r\n";
        insta::assert_snapshot!(run(&ARTIFACT, "root/.viminfo", data, 0));
    }

    #[test]
    fn history_of_marks_within_files_lists_the_edited_files() {
        let data = b"# History of marks within files (newest to oldest):\n\n> /etc/cron.d/x\n\t\"\t1\t0\n\t^\t1\t1\n\n> /home/a b/c\n\t\"\t2\t0\n";
        let out = run(&ARTIFACT, "root/.viminfo", data, 0);
        assert_eq!(out.matches("\"kind\":\"file_mark\"").count(), 2, "{out}");
        assert!(out.contains("\"text\":\"/etc/cron.d/x\"") && out.contains("\"text\":\"/home/a b/c\""), "{out}");
    }

    #[test]
    fn bar_lines_alone_and_escapes() {
        let data = b"|2,0,1700000000,,\"echo \\\"x\\\"\\\\y\\nz\"\n|2,1,1700000001,,\"a,b\"\n|4,39,5,0,1700000002,\"/x,y\"\n|3,0,1,,\"\"\n|2,9\n";
        insta::assert_snapshot!(run(&ARTIFACT, "root/.viminfo", data, 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "root/.viminfo", b"", 0), "");
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "root/.viminfo", &garbage, 0);
        run(&ARTIFACT, "root/.viminfo", b"|4\n|4,1\n|2,0,5\n|2,0,5,,\"\n", 0);
    }
}

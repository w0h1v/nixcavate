//! fish history: `~/.local/share/fish/fish_history`. fish's own YAML-like format: entries
//! `- cmd: <text>`, `  when: <epoch>` and an optional `  paths:` list. The text escapes
//! backslash as `\\` and newline as `\n`.

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "fish-history",
    "Fish shell command history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.local/share/fish/fish_history",
        "root/.local/share/fish/fish_history",
        "Users/*/.local/share/fish/fish_history",
        "private/var/root/.local/share/fish/fish_history",
        "var/root/.local/share/fish/fish_history",
    ],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    user: &'a str,
    time: Option<Timestamp>,
    command: String,
    /// Files the command referred to that existed when it ran.
    paths: Vec<String>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "executed", format!("{} ran {}", self.user, self.command))).into_iter()
    }
}

fn unescape(bytes: &[u8]) -> String {
    let text = lossy(bytes);
    if !text.contains('\\') {
        return text.into_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (c, chars.as_str().chars().next()) {
            ('\\', Some('\\')) => out.push('\\'),
            ('\\', Some('n')) => out.push('\n'),
            _ => {
                out.push(c);
                continue;
            }
        }
        chars.next();
    }
    out
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let mut current: Option<(u64, Entry)> = None;
    for_each_line(input, |line| {
        if let Some(cmd) = line.bytes.strip_prefix(b"- cmd:") {
            if let Some((number, entry)) = current.take() {
                sink.emit(Loc::Line(number), &entry)?;
            }
            let cmd = cmd.strip_prefix(b" ").unwrap_or(cmd);
            current = Some((line.number, Entry { user, time: None, command: unescape(cmd), paths: Vec::new() }));
        } else if let Some((_, entry)) = current.as_mut() {
            if let Some(when) = line.bytes.strip_prefix(b"  when:") {
                let secs = parse_uint(when.trim_ascii()).and_then(|s| i64::try_from(s).ok());
                entry.time = secs.map(|s| Timestamp::from_secs(s, Basis::Recorded));
            } else if let Some(path) = line.bytes.strip_prefix(b"    - ") {
                entry.paths.push(unescape(path));
            }
        }
        Ok(())
    })?;
    match current {
        Some((number, entry)) => sink.emit(Loc::Line(number), &entry),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn history_from_fish() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "root/.local/share/fish/fish_history",
            &fixture("fish-history/fish_history"),
            0
        ));
    }

    #[test]
    fn escapes_paths_and_crlf() {
        let data = fixture("fish-history/escapes");
        insta::assert_snapshot!(run(&ARTIFACT, "Users/sam/.local/share/fish/fish_history", &data, 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "root/.local/share/fish/fish_history", b"", 0), "");
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "root/.local/share/fish/fish_history", &garbage, 0);
    }
}

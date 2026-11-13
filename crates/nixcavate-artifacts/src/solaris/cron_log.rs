//! `var/cron/log`: what the cron daemon ran. Lines, as `cron` writes them:
//!
//! * `>  CMD: COMMAND` names the command of the job that starts on the next `>` line;
//! * `>  USER PID TYPE TIME` is a job starting (`c` cron, `a` at, `b` batch);
//! * `<  USER PID TYPE TIME[ rc=N]` is the same job ending; `rc=` appears only for a non-zero
//!   exit status;
//! * `! *** cron started ***   pid = N TIME`, `! SIGTERM TIME` and `! ******* CRON ABORTED ***`
//!   are daemon events.
//!
//! `TIME` is `ctime(3)` text, with a year and no zone. An end line carries no command, so it is
//! matched to the start line with the same process id earlier in the file. Verified on illumos
//! against the jobs the harness scheduled (11 starts, 11 ends, one `rc=127`).

use super::when::ctime_time;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::collections::HashMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "cron-log",
    "Cron job starts, ends and exit codes (Solaris/illumos cron log)",
    Category::Execution,
    SOLARIS,
    &["var/cron/log*", "var/share/cron/log*"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    /// `start`, `end` or `daemon`.
    event: &'static str,
    user: &'a str,
    pid: Option<u32>,
    /// `c` (cron), `a` (at) or `b` (batch); empty for daemon events.
    job_type: &'a str,
    /// The command, for a start and (matched by process id) for an end.
    command: Option<String>,
    exit_status: Option<i32>,
    /// The text of a daemon event.
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let command = self.command.as_deref().unwrap_or("(unknown command)");
        let (kind, message) = match self.event {
            "start" => ("executed", format!("cron started {command} as {}", self.user)),
            // Only a failure is worth a line of its own; a clean end is in the record.
            "end" => match self.exit_status {
                Some(rc) if rc != 0 => {
                    ("executed", format!("cron job {command} as {} ended with status {rc}", self.user))
                }
                _ => return None.into_iter(),
            },
            _ => ("log", format!("cron: {}", self.message)),
        };
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut pending: Option<String> = None;
    let mut by_pid: HashMap<u32, String> = HashMap::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let loc = Loc::Line(line.number);
        let Some((mark, rest)) = text.split_at_checked(1) else { return Ok(()) };
        let rest = rest.trim();
        match mark {
            "!" => {
                let time = daemon_time(input, rest);
                sink.emit(
                    loc,
                    &Entry {
                        time,
                        event: "daemon",
                        user: "",
                        pid: None,
                        job_type: "",
                        command: None,
                        exit_status: None,
                        message: rest,
                    },
                )
            }
            ">" | "<" => {
                if let Some(command) = rest.strip_prefix("CMD:") {
                    pending = Some(command.trim().to_string());
                    return Ok(());
                }
                let mut words = rest.splitn(4, char::is_whitespace);
                let (Some(user), Some(pid), Some(kind), Some(when)) =
                    (words.next(), words.next(), words.next(), words.next())
                else {
                    sink.warn(format!("line {}: not a cron job line", line.number));
                    return Ok(());
                };
                let Ok(pid) = pid.parse::<u32>() else {
                    sink.warn(format!("line {}: the process id is not a number", line.number));
                    return Ok(());
                };
                let (when, exit_status) = match when.rsplit_once(" rc=") {
                    Some((when, rc)) => (when, rc.trim().parse::<i32>().ok()),
                    None => (when, None),
                };
                let starting = mark == ">";
                let command = if starting {
                    let command = pending.take();
                    if let Some(c) = &command {
                        // Bounded: a log cannot make the table grow without limit.
                        if by_pid.len() < 100_000 {
                            by_pid.insert(pid, c.clone());
                        }
                    }
                    command
                } else {
                    by_pid.get(&pid).cloned()
                };
                // An ended job with a zero status has no `rc=`: the end of a job is still a fact.
                let exit_status = if starting { None } else { exit_status.or(Some(0)) };
                sink.emit(
                    loc,
                    &Entry {
                        time: ctime_time(input, when),
                        event: if starting { "start" } else { "end" },
                        user,
                        pid: Some(pid),
                        job_type: kind,
                        command,
                        exit_status,
                        message: "",
                    },
                )
            }
            _ => {
                sink.warn(format!("line {}: not a cron log line", line.number));
                Ok(())
            }
        }
    })
}

/// The time at the end of a daemon line: the last five words (`Fri Nov 13 01:20:29 2026`).
fn daemon_time(input: &Input, text: &str) -> Option<Timestamp> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let tail = words.get(words.len().checked_sub(5)?..)?;
    ctime_time(input, &tail.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_cron_log() {
        let out = run(&ARTIFACT, "var/cron/log", &fixture("cron-log/log"), 0);
        insta::assert_snapshot!(out);
        let count = |what: &str| out.matches(what).count();
        assert_eq!(
            (count(r#""event":"start""#), count(r#""event":"end""#), count(r#""event":"daemon""#)),
            (5, 5, 4),
            "{out}"
        );
        // An end line has no command: it gets the one of the start line with its process id.
        assert!(out.contains(r#""event":"end","user":"root","pid":1693,"job_type":"c","command":"/tmp/.NXMK_CRON/agent --quiet","exit_status":127"#), "{out}");
        assert!(out.contains(r#""event":"end","user":"alice","pid":1687,"job_type":"c","command":"/usr/bin/true #nxcron-every-minute","exit_status":0"#), "{out}");
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(timeline.contains("ended with status 127") && !timeline.contains("ended with status 0"), "{timeline}");
    }

    #[test]
    fn a_reused_pid_takes_the_latest_command_and_odd_lines_warn() {
        let log = b">  CMD: first\n>  root 7 c Fri Nov 13 01:00:00 2026\n<  root 7 c Fri Nov 13 01:00:01 2026\n>  CMD: second\n>  root 7 c Fri Nov 13 01:01:00 2026\n<  root 7 c Fri Nov 13 01:01:01 2026 rc=1\nbad\n>  root x c nope\n";
        let out = run(&ARTIFACT, "var/cron/log", log, 0);
        assert!(
            out.contains(r#""command":"second","exit_status":1"#)
                && out.contains(r#""command":"first","exit_status":0"#),
            "{out}"
        );
        assert!(out.contains("not a cron log line") && out.contains("the process id is not a number"), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/cron/log", &fixture("cron-log/log"));
    }
}

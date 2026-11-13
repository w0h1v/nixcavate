//! `var/adm/cron/log`: the cron daemon's own record of each job it started and ended.
//!
//! ```text
//! ! *** cron started ***   pid = 6291650 Wed Mar 10 08:57:34 2021
//! >  CMD: /usr/lib/ras/dumpcheck >/dev/null 2>&1
//! >  root 8126588 c Wed Mar 10 09:00:00 2021
//! <  root 8126588 c Wed Mar 10 09:00:01 2021
//! ```
//!
//! `>` starts a job (its command is on the `CMD:` line before it), `<` ends it, `!` is the daemon
//! itself. Times are wall-clock in the host zone. This is the System V cron log; no real AIX file
//! was available and the layout is written from the format's long-standing shape, so it is
//! **synthetic only**: a line that fits none of the forms is a warning.

use super::clock::ctime;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("aix-cron-log", "AIX cron job runs", Category::Execution, AIX, &["var/adm/cron/log*"], parse);

#[derive(Serialize)]
struct Entry<'a> {
    /// `start`, `end`, `daemon_started` or `message`.
    kind: &'static str,
    time: Option<Timestamp>,
    user: Option<&'a str>,
    pid: Option<u32>,
    /// `c` for cron, `a` for at, `b` for batch.
    job_type: Option<&'a str>,
    command: Option<String>,
    text: Option<&'a str>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, message) = match self.kind {
            "start" => (
                "executed",
                format!(
                    "cron started {} job of {}: {}",
                    self.job_type.unwrap_or("?"),
                    self.user.unwrap_or("?"),
                    self.command.as_deref().unwrap_or("(command not logged)")
                ),
            ),
            "daemon_started" => ("log", "cron daemon started".to_string()),
            _ => return None.into_iter(),
        };
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

/// `root 8126588 c Wed Mar 10 09:00:00 2021`
fn job_line(rest: &str) -> Option<(&str, u32, &str, i64)> {
    let mut parts = rest.split_whitespace();
    let (user, pid, kind) = (parts.next()?, parts.next()?.parse().ok()?, parts.next()?);
    let remainder = rest.trim_start().splitn(4, char::is_whitespace).nth(3)?;
    if kind.len() != 1 {
        return None;
    }
    Some((user, pid, kind, ctime(remainder)?))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut command: Option<String> = None;
    let stamp = |wall: i64| input.local_time(wall, 0, Precision::Seconds);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        let loc = Loc::Line(line.number);
        if let Some(rest) = text.strip_prefix('>') {
            let rest = rest.trim_start();
            if let Some(cmd) = rest.strip_prefix("CMD:") {
                command = Some(cmd.trim().to_string());
                return Ok(());
            }
            return match job_line(rest) {
                Some((user, pid, kind, wall)) => sink.emit(
                    loc,
                    &Entry {
                        kind: "start",
                        time: Some(stamp(wall)),
                        user: Some(user),
                        pid: Some(pid),
                        job_type: Some(kind),
                        command: command.take(),
                        text: None,
                    },
                ),
                None => {
                    sink.warn(format!("line {}: not a cron start line", line.number));
                    Ok(())
                }
            };
        }
        if let Some(rest) = text.strip_prefix('<') {
            return match job_line(rest.trim_start()) {
                Some((user, pid, kind, wall)) => sink.emit(
                    loc,
                    &Entry {
                        kind: "end",
                        time: Some(stamp(wall)),
                        user: Some(user),
                        pid: Some(pid),
                        job_type: Some(kind),
                        command: None,
                        text: None,
                    },
                ),
                None => {
                    sink.warn(format!("line {}: not a cron end line", line.number));
                    Ok(())
                }
            };
        }
        if let Some(rest) = text.strip_prefix('!') {
            let rest = rest.trim();
            let started = rest.strip_prefix("*** cron started ***").and_then(|r| {
                let r = r.trim_start().strip_prefix("pid =")?.trim_start();
                let (pid, when) = r.split_once(char::is_whitespace)?;
                Some((pid.parse().ok()?, ctime(when)?))
            });
            return match started {
                Some((pid, wall)) => sink.emit(
                    loc,
                    &Entry {
                        kind: "daemon_started",
                        time: Some(stamp(wall)),
                        user: None,
                        pid: Some(pid),
                        job_type: None,
                        command: None,
                        text: None,
                    },
                ),
                None => sink.emit(
                    loc,
                    &Entry {
                        kind: "message",
                        time: None,
                        user: None,
                        pid: None,
                        job_type: None,
                        command: None,
                        text: Some(rest),
                    },
                ),
            };
        }
        sink.warn(format!("line {}: not a cron log line", line.number));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    const LOG: &[u8] = b"! *** cron started ***   pid = 6291650 Wed Mar 10 08:57:34 2021\n>  CMD: /usr/lib/ras/dumpcheck >/dev/null 2>&1\n>  root 8126588 c Wed Mar 10 09:00:00 2021\n<  root 8126588 c Wed Mar 10 09:00:01 2021\n>  CMD: /tmp/.x/miner -o pool\n>  alice 8126600 c Wed Mar 10 09:05:00 2021\n! cron: can't read /var/spool/cron/crontabs/bob\ngarbage\n";

    #[test]
    fn jobs_start_and_end() {
        let out = run(&ARTIFACT, "var/adm/cron/log", LOG, 0);
        assert!(out.contains(r#""kind":"start""#) && out.contains("/usr/lib/ras/dumpcheck"), "{out}");
        assert!(out.contains("alice") && out.contains("not a cron log line"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn hostile() {
        for data in [&b""[..], b">", b"<  x\n!\n>  CMD:", b"\xff\x80\n>\xff", &[b'>'; 4000][..]] {
            let _ = run(&ARTIFACT, "var/adm/cron/log", data, 0);
        }
    }
}

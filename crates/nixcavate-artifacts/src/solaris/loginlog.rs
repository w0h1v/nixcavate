//! `var/adm/loginlog`: failed console logins. `login(1)` appends `user:tty:time` for each failed
//! attempt once the user has failed `RETRIES` times in a row (5 by default), and only when the
//! file exists. The time is `ctime(3)` text with a year and no zone.
//!
//! Verified on illumos: five lines for five failed attempts through `login`. The sshd failures
//! do not go here; they are in the authentication log.

use super::when::ctime_time;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "loginlog",
    "Failed console logins after repeated attempts (Solaris/illumos loginlog)",
    Category::Accounts,
    SOLARIS,
    &["var/adm/loginlog*", "var/share/adm/loginlog*"],
    parse,
);

#[derive(Serialize)]
struct Failure<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    tty: &'a str,
}

impl Record for Failure<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("failed login as {} on {}", self.user, self.tty);
        self.time.map(|ts| Event::new(ts, "failed_login", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        // The user name cannot hold `:`, the time does (`01:15:46`), so only two splits are made.
        let mut parts = text.splitn(3, ':');
        let (Some(user), Some(tty), Some(when)) = (parts.next(), parts.next(), parts.next()) else {
            sink.warn(format!("line {}: expected user:tty:time", line.number));
            return Ok(());
        };
        sink.emit(Loc::Line(line.number), &Failure { time: ctime_time(input, when), user, tty })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// Five failed `login` attempts for `mallory` on `/dev/pts/1`, as `login` wrote them.
    #[test]
    fn a_real_loginlog() {
        let out = run(&ARTIFACT, "var/adm/loginlog", &fixture("loginlog/loginlog"), 0);
        insta::assert_snapshot!(out);
        assert_eq!(out.matches("\"user\":\"mallory\"").count(), 5);
        assert!(out.contains(r#""time":"2026-11-13T01:15:46Z""#) && !out.contains(r#""time_basis""#), "{out}");
        assert!(out.contains("failed login as mallory on /dev/pts/1"), "{out}");
    }

    #[test]
    fn bad_lines_are_warnings() {
        let out = run(
            &ARTIFACT,
            "var/adm/loginlog",
            b"nocolons\nuser:tty:not a time\n\nuser:/dev/pts/1:Fri Nov 13 01:15:46 2026\n",
            0,
        );
        assert!(out.contains("expected user:tty:time"), "{out}");
        assert!(out.contains(r#""user":"user","tty":"/dev/pts/1""#) && out.contains(r#""time":null"#), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/adm/loginlog", &fixture("loginlog/loginlog"));
    }
}

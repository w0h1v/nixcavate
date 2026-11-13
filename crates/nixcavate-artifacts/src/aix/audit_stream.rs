//! `audit/stream.out` and other `auditpr` text: one event per row under the header
//! `event login status time command`, followed by indented detail lines.
//!
//! ```text
//! event                  login    status      time                       command
//! ---------------------- -------- ----------- -------------------------- --------------
//! USER_SU                root     OK          Wed Mar 10 09:00:00 2021   su
//!     ...detail...
//! ```
//!
//! The columns are those of `auditpr -v` as described for the stream mode of AIX auditing, which
//! the task brief names; no real file was available and IBM's page could not be fetched, so this
//! is **synthetic only**. Only rows that fit (a name, a user, a status word, a ctime-style time
//! and a command) are read; everything else is a detail line of the previous row or ignored.
//! The binary audit trail (`audit/trail`) is not read.

use super::clock::ctime;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "aix-audit-stream",
    "AIX audit events (auditpr text output)",
    Category::Security,
    AIX,
    &["audit/stream.out*", "audit/*.out", "var/adm/audit/stream.out*"],
    parse,
);

#[derive(Serialize)]
struct AuditEvent<'a> {
    event: &'a str,
    login: &'a str,
    status: &'a str,
    time: Timestamp,
    command: &'a str,
}

impl Record for AuditEvent<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        Some(Event::new(
            self.time,
            "audit_event",
            format!(
                "{} by {} ({}){}",
                self.event,
                self.login,
                self.status,
                if self.command.is_empty() { String::new() } else { format!(": {}", self.command) }
            ),
        ))
        .into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let (mut header, mut rows, mut other) = (false, 0u64, 0u64);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with("---") {
            return Ok(());
        }
        if trimmed.starts_with("event") && trimmed.contains("login") && trimmed.contains("status") {
            header = true;
            return Ok(());
        }
        // A row starts at the left margin; its detail lines are indented.
        if text.starts_with([' ', '\t']) {
            return Ok(());
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        let row = (|| {
            let [event, login, status, rest @ ..] = &words[..] else { return None };
            // The time is the next five or six words (`Wed Mar 10 09:00:00 [UTC] 2021`).
            (5..=6).find_map(|n| {
                let when = ctime(&rest.get(..n)?.join(" "))?;
                Some((*event, *login, *status, when, rest[n..].join(" ")))
            })
        })();
        match row {
            Some((event, login, status, when, command)) => {
                rows += 1;
                sink.emit(
                    Loc::Line(line.number),
                    &AuditEvent {
                        event,
                        login,
                        status,
                        time: input.local_time(when, 0, Precision::Seconds),
                        command: &command,
                    },
                )
            }
            None => {
                other += 1;
                Ok(())
            }
        }
    })?;
    if !header && rows == 0 {
        sink.warn("no `event login status time command` header or rows: not auditpr text output (the binary audit trail is not read)");
    } else if other > 0 {
        sink.warn(format!("{other} unindented lines did not fit the event row layout and were not read"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn rows_become_events() {
        let data = b"event                  login    status      time                       command\n---------------------- -------- ----------- -------------------------- --------------\nUSER_SU                root     OK          Wed Mar 10 09:00:00 2021   su\n    detail line\nFILE_Mode              alice    FAIL        Wed Mar 10 09:01:00 2021   chmod\nCRON_Start             root     OK          Wed Mar 10 09:02:00 UTC 2021   cron\nweird unindented\n";
        let out = run(&ARTIFACT, "audit/stream.out", data, 0);
        assert_eq!(out.matches("\"event\":").count(), 3, "{out}");
        assert!(out.contains("1 unindented lines"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn binary_trail_is_named_not_read() {
        let out = run(&ARTIFACT, "audit/stream.out", &[0x00, 0x01, 0xff, 0xfe, b'x', 0x80], 0);
        assert!(out.contains("not auditpr text output"), "{out}");
    }

    #[test]
    fn hostile() {
        for data in [&b""[..], b"event login status\nA B\nA B C D E F G\n", &[b'e'; 5000][..]] {
            let _ = run(&ARTIFACT, "audit/stream.out", data, 0);
        }
    }
}

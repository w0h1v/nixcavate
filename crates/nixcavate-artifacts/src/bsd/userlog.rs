//! FreeBSD `/var/log/userlog`: account changes written by `pw(8)`, `adduser(8)` and `rmuser(8)`:
//! `2026-01-02 03:04:05 [actor:tool] name(uid):...`. The time has no zone: the host zone is
//! applied and marked as assumed.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, FREEBSD};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "userlog",
    "FreeBSD account changes (pw, adduser, rmuser)",
    Category::Accounts,
    FREEBSD,
    &["var/log/userlog*"],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    /// The account that ran the tool (`root`), or `unknown`.
    actor: &'a str,
    /// `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`...
    tool: &'a str,
    message: &'a str,
    /// The account or group changed: the name before the first `(`.
    subject: &'a str,
    /// `account_created`, `account_modified`, `account_deleted`, `group_created`, ... or empty.
    event: &'static str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        if self.event.is_empty() {
            return None.into_iter();
        }
        let message = format!("{} {} by {}", self.tool, self.subject, self.actor);
        self.time.map(|t| Event::new(t, self.event, message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() {
            return Ok(());
        }
        // `YYYY-MM-DD HH:MM:SS [actor:tool] message`
        let parsed = text.get(..19).and_then(|stamp| parse_iso8601(stamp.as_bytes())).filter(|(_, used)| *used == 19);
        let rest = text.get(20..).unwrap_or_default();
        let (tag, message) = rest.strip_prefix('[').and_then(|r| r.split_once("] ")).unwrap_or(("", &text));
        let (actor, tool) = tag.split_once(':').unwrap_or(("", tag));
        let time = parsed.map(|(t, _)| t.recorded().unwrap_or_else(|| input.local_time(t.secs, 0, Precision::Seconds)));
        let subject = message.split('(').next().unwrap_or_default();
        let event = match tool {
            "useradd" if !message.contains(" home ") => "account_created",
            "usermod" => "account_modified",
            "userdel" => "account_deleted",
            "groupadd" => "group_created",
            "groupmod" => "group_modified",
            "groupdel" => "group_deleted",
            _ => "",
        };
        if parsed.is_none() {
            sink.warn(format!("line {}: no timestamp", line.number));
        }
        sink.emit(Loc::Offset(line.offset), &Entry { time, actor, tool, message, subject, event })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_userlog() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/userlog", &fixture("userlog/userlog"), 0));
    }

    #[test]
    fn events_follow_the_tool_and_odd_lines_keep_their_text() {
        let log = "2026-11-13 01:08:29 [root:useradd] alice(1002):alice(1002):Alice:/home/alice:/bin/sh\n\
                   2026-11-13 01:08:29 [root:useradd] alice(1002) home /home/alice made\n\
                   2026-11-13 01:09:00 [root:userdel] alice(1002) removed\n\
                   no timestamp here\n";
        let out = run(&ARTIFACT, "var/log/userlog", log.as_bytes(), 0);
        assert_eq!(out.matches(",account_created,").count(), 1, "{out}");
        assert!(out.contains("account_deleted"));
        assert!(out.contains("--- warning: line 4: no timestamp"));
    }
}

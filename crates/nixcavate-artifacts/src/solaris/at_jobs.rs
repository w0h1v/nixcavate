//! `var/spool/cron/atjobs/*`: jobs queued with at(1). The file is named `EPOCH.QUEUE`
//! (`1794791809.a`: run at that time, in queue `a`) and is a shell script written by `at`:
//! header lines (`: at job`, `: jobname: stdin`, `: notify by mail: no`, `: project: 3`), the
//! submitter's environment as `export NAME; NAME='value'`, the line `$SHELL << '...the rest of
//! this file is shell input'`, then `cd '/dir'`, `umask N` and the commands. The owner is the
//! file's owner; `LOGNAME` in the environment is who submitted it. A `.au` file beside each job
//! holds audit information and is not a job.
//!
//! Verified on illumos against `atq`: the same run time and owner for the job the harness queued.

use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "solaris-at-jobs",
    "Jobs queued with at(1) (Solaris/illumos)",
    Category::Persistence,
    SOLARIS,
    &["var/spool/cron/atjobs/*", "var/share/spool/cron/atjobs/*"],
    parse,
);

#[derive(Serialize)]
struct Job<'a> {
    queue: &'a str,
    /// When the job is due to run (from the file name).
    time: Option<Timestamp>,
    /// The owner of the job file.
    uid: u32,
    job_name: &'a str,
    mail: &'a str,
    project: &'a str,
    /// `LOGNAME` of the environment the job was submitted from.
    submitted_by: &'a str,
    working_dir: &'a str,
    umask: &'a str,
    /// The user's commands, one per line of the script, joined by `; `.
    command: Option<String>,
    environment: Vec<&'a str>,
}

impl Record for Job<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = self.command.as_deref().unwrap_or("(no command found)");
        let message = format!("at job scheduled to run as uid {}: {what}", self.uid);
        self.time.map(|ts| Event::new(ts, "scheduled_job", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    if name.ends_with(".au") {
        return Err(Error::skipped("audit information that belongs to a job, not a job"));
    }
    let Some((epoch, queue)) = name.split_once('.').filter(|(e, q)| !e.is_empty() && q.len() == 1) else {
        return Err(Error::format("the file name is not EPOCH.QUEUE"));
    };
    let time = parse_uint(epoch.as_bytes())
        .and_then(|t| i64::try_from(t).ok())
        .map(|t| Timestamp::from_secs(t, Basis::Recorded));
    let (mut job_name, mut mail, mut project) = ("", "", "");
    let (mut submitted_by, mut working_dir, mut umask) = ("", "", "");
    let mut environment = Vec::new();
    let mut commands: Vec<String> = Vec::new();
    let mut in_script = false;
    let mut seen_marker = false;
    let text = lossy(input.data);
    for line in text.lines() {
        let trimmed = line.trim();
        if !in_script {
            if let Some(rest) = trimmed.strip_prefix(": ") {
                if let Some(v) = rest.strip_prefix("jobname: ") {
                    job_name = v;
                } else if let Some(v) = rest.strip_prefix("notify by mail: ") {
                    mail = v;
                } else if let Some(v) = rest.strip_prefix("project: ") {
                    project = v;
                }
            } else if let Some(rest) = trimmed.strip_prefix("export ") {
                if let Some((_, assign)) = rest.split_once("; ") {
                    if let Some(v) = assign.strip_prefix("LOGNAME=") {
                        submitted_by = v.trim_matches('\'');
                    }
                    if environment.len() < 1000 {
                        environment.push(assign);
                    }
                }
            } else if trimmed.contains("the rest of this file is shell input") {
                in_script = true;
                seen_marker = true;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(dir) = trimmed.strip_prefix("cd ").filter(|_| working_dir.is_empty() && commands.is_empty()) {
            working_dir = dir.trim_matches('\'');
        } else if let Some(mask) = trimmed.strip_prefix("umask ").filter(|_| umask.is_empty() && commands.is_empty()) {
            umask = mask;
        } else if commands.len() < 10_000 {
            commands.push(trimmed.to_string());
        }
    }
    if !seen_marker {
        sink.warn("no `the rest of this file is shell input` line: the commands could not be told from the header");
    }
    sink.emit(
        Loc::None,
        &Job {
            queue,
            time,
            uid: input.uid,
            job_name,
            mail,
            project,
            submitted_by,
            working_dir,
            umask,
            command: (!commands.is_empty()).then(|| commands.join("; ")),
            environment,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// `atq` printed `1st Nov 16, 2026 01:16 root 1794791809.a a stdin` for this file, which `at` wrote.
    #[test]
    fn a_real_at_job_equals_atq() {
        let out = run(
            &ARTIFACT,
            "var/spool/cron/atjobs/1794791809.a",
            &fixture("solaris-at-jobs/1794791809.a"),
            1_794_532_609,
        );
        insta::assert_snapshot!(out);
        let atq = String::from_utf8(fixture("solaris-at-jobs/atq.txt")).unwrap();
        assert!(atq.contains("Nov 16, 2026 01:16") && atq.contains("1794791809.a"));
        for want in [
            r#""queue":"a","time":"2026-11-16T01:16:49Z","uid":0,"job_name":"stdin","mail":"no","project":"3","submitted_by":"omnios""#,
            r#""working_dir":"/home/omnios","umask":"22","command":"/tmp/.NXMK_AT/agent --quiet""#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        assert!(out.contains("scheduled_job"), "{out}");
    }

    #[test]
    fn the_audit_file_the_name_and_a_missing_marker() {
        assert!(run(&ARTIFACT, "var/spool/cron/atjobs/1794791809.a.au", b"100\n1000\n", 0).contains("not a job"));
        assert!(run(&ARTIFACT, "var/spool/cron/atjobs/job", b"x", 0).contains("not EPOCH.QUEUE"));
        let out = run(&ARTIFACT, "var/spool/cron/atjobs/1700000000.b", b": at job\nid\n", 0);
        assert!(
            out.contains("no `the rest of this file is shell input` line") && out.contains(r#""queue":"b""#),
            "{out}"
        );
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(
            &ARTIFACT,
            "var/spool/cron/atjobs/1794791809.a",
            &fixture("solaris-at-jobs/1794791809.a"),
        );
    }
}

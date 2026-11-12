//! anacron: the job table `etc/anacrontab` and the per-job timestamp files in
//! `var/spool/anacron/`. Format: anacrontab(5), anacron(8). A timestamp file holds the
//! calendar day (`YYYYMMDD`) on which the job last ran.

use crate::common::cron::{env_assignment, token};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{civil_from_days, days_from_civil, parse_uint};
use nixcavate_core::{Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "anacron",
    "anacron job table and last-run timestamps",
    Category::Persistence,
    LINUX,
    &["etc/anacrontab", "var/spool/anacron/*"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    /// `job`, `env` or `last_run`.
    kind: &'static str,
    /// Days as written, or `@daily`/`@weekly`/`@monthly`/`@yearly`/`@annually`.
    period: Option<&'a str>,
    delay_minutes: Option<u32>,
    job_id: Option<&'a str>,
    command: Option<&'a str>,
    name: Option<&'a str>,
    value: Option<&'a str>,
    /// A calendar day with no zone, so the basis is `AssumedZone`.
    last_run: Option<Timestamp>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.last_run
            .map(|ts| {
                Event::new(ts, "anacron_last_run", format!("anacron job {} last ran", self.job_id.unwrap_or_default()))
            })
            .into_iter()
    }
}

fn empty(kind: &'static str) -> Entry<'static> {
    Entry {
        kind,
        period: None,
        delay_minutes: None,
        job_id: None,
        command: None,
        name: None,
        value: None,
        last_run: None,
    }
}

fn valid_period(period: &str) -> bool {
    matches!(period, "@daily" | "@weekly" | "@monthly" | "@yearly" | "@annually")
        || (!period.is_empty() && period.bytes().all(|b| b.is_ascii_digit()))
}

/// `period delay job-identifier command`.
fn job(text: &str) -> Option<Entry<'_>> {
    let (period, rest) = token(text)?;
    let (delay, rest) = token(rest)?;
    let (job_id, command) = token(rest)?;
    if !valid_period(period) || command.is_empty() {
        return None;
    }
    let delay_minutes = parse_uint(delay.as_bytes()).and_then(|d| u32::try_from(d).ok())?;
    Some(Entry {
        period: Some(period),
        delay_minutes: Some(delay_minutes),
        job_id: Some(job_id),
        command: Some(command),
        ..empty("job")
    })
}

fn day(input: &Input, text: &str) -> Option<Timestamp> {
    let text = text.trim().as_bytes();
    if text.len() != 8 {
        return None;
    }
    let year = parse_uint(&text[..4])? as i64;
    let (month, mday) = (parse_uint(&text[4..6])? as u32, parse_uint(&text[6..])? as u32);
    let days = days_from_civil(year, month, mday);
    // Reject impossible dates such as 20260231 by checking the round trip.
    (civil_from_days(days) == (year, month, mday))
        .then(|| input.local_time(days.saturating_mul(86_400), 0, Precision::Day))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.path.contains("var/spool/anacron/") {
        let job_id = input.path.rsplit('/').next().unwrap_or_default();
        let text = lossy(input.data);
        if text.trim().is_empty() {
            return Err(Error::skipped("empty timestamp file"));
        }
        let last_run = day(input, &text);
        if last_run.is_none() {
            sink.warn(format!("{job_id}: not a YYYYMMDD date"));
        }
        return sink.emit(Loc::None, &Entry { job_id: Some(job_id), last_run, ..empty("last_run") });
    }
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let loc = Loc::Line(line.number);
        if let Some((name, value)) = env_assignment(text) {
            return sink.emit(loc, &Entry { name: Some(name), value: Some(value), ..empty("env") });
        }
        match job(text) {
            Some(entry) => sink.emit(loc, &entry),
            None => {
                sink.warn(format!("line {}: not an anacrontab entry", line.number));
                sink.emit(loc, &Entry { command: Some(text), ..empty("job") })
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn debian_and_rhel_tables() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/anacrontab", &fixture("anacron/anacrontab-debian"), 0));
        insta::assert_snapshot!(run(&ARTIFACT, "etc/anacrontab", &fixture("anacron/anacrontab-rocky"), 0));
    }

    #[test]
    fn timestamp_file() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "var/spool/anacron/cron.daily",
            &fixture("anacron/stamp-cron.daily"),
            0
        ));
    }

    #[test]
    fn timestamp_day_uses_the_host_zone() {
        let zone = fixture("dpkg-log/Europe_Berlin.tzif");
        let path = "var/spool/anacron/cron.daily";
        let files: [(&str, &[u8]); 2] = [("etc/localtime", &zone), (path, b"20260105\n")];
        let out = run_on_host(&ARTIFACT, &files, path, 0);
        assert!(out.contains("\"last_run\":\"2026-01-04T23:00:00Z\""), "{out}");
    }

    #[test]
    fn bad_input_does_not_panic() {
        assert_eq!(run(&ARTIFACT, "etc/anacrontab", b"", 0), "");
        let out = run(&ARTIFACT, "var/spool/anacron/x", b"20260231\n", 0);
        assert!(out.contains("warning"));
        let _ = run(&ARTIFACT, "var/spool/anacron/x", b"\xff\x00", 0);
        let _ = run(&ARTIFACT, "etc/anacrontab", b"@weekly\n1 x job cmd\n9999999999999 1 a b\n\xff\n", 0);
    }
}

//! Scheduled jobs run by cron. Formats: crontab(5) for the tables; the `cron.*` and
//! `periodic` directories hold scripts that run because of where they sit, not what they say.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const CRON: Artifact = Artifact::new(
    "cron",
    "Crontab entries: system and user crontabs",
    Category::Persistence,
    ANY_OS,
    &[
        "etc/crontab",
        "etc/cron.d/*",
        "var/spool/cron/crontabs/*",
        "var/spool/cron/*",
        // Alpine's busybox crond, and SUSE.
        "etc/crontabs/*",
        "var/spool/cron/tabs/*",
        "usr/lib/cron/tabs/*",
        "private/var/at/tabs/*",
        "private/etc/crontab",
        // FreeBSD, OpenBSD and NetBSD.
        "var/cron/tabs/*",
    ],
    parse,
);

pub const SCRIPTS: Artifact = Artifact::new(
    "cron-scripts",
    "Scripts in cron.hourly/daily/weekly/monthly and periodic directories",
    Category::Persistence,
    ANY_OS,
    &[
        "etc/cron.hourly/*",
        "etc/cron.daily/*",
        "etc/cron.weekly/*",
        "etc/cron.monthly/*",
        "etc/periodic/daily/*",
        "etc/periodic/weekly/*",
        "etc/periodic/monthly/*",
        "private/etc/periodic/*/*",
        "usr/local/etc/periodic/*/*",
        // FreeBSD, OpenBSD and NetBSD.
        "etc/daily.local",
        "etc/weekly.local",
        "etc/monthly.local",
        "etc/security.local",
        "etc/daily",
        "etc/weekly",
        "etc/monthly",
    ],
    crate::common::script::file_info,
);

#[derive(Serialize)]
struct Entry<'a> {
    /// `job` or `env`.
    kind: &'static str,
    /// The five time fields, or the `@reboot`/`@daily` nickname.
    schedule: Option<String>,
    /// The account the job runs as; for an `env` line, the owner of a user crontab.
    user: Option<&'a str>,
    command: Option<&'a str>,
    name: Option<&'a str>,
    value: Option<&'a str>,
}

impl Record for Entry<'_> {}

const NICKNAMES: &[&str] =
    &["@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"];

/// The next whitespace-delimited token and the text after it.
pub(crate) fn token(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if text.is_empty() {
        return None;
    }
    let end = text.find(char::is_whitespace).unwrap_or(text.len());
    Some((&text[..end], text[end..].trim_start()))
}

/// `NAME = value`, the value optionally quoted. Job lines never match: their first field
/// has no `=` before the first space.
pub(crate) fn env_assignment(text: &str) -> Option<(&str, &str)> {
    let (name, value) = text.split_once('=')?;
    let name = name.trim_end();
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let value = value.trim();
    let unquoted = ['"', '\''].into_iter().find_map(|q| value.strip_prefix(q)?.strip_suffix(q));
    Some((name, unquoted.unwrap_or(value)))
}

/// Minute, hour and day-of-month are numeric; month and weekday may be names.
fn valid_field(field: &str, index: usize) -> bool {
    field.bytes().all(|b| {
        b.is_ascii_digit() || matches!(b, b'*' | b'/' | b',' | b'-' | b'?') || (index >= 3 && b.is_ascii_alphabetic())
    })
}

/// Splits a job line into (schedule, user, command); `None` when it is not a job.
fn job(text: &str, system: bool) -> Option<(String, Option<&str>, &str)> {
    let text = text.trim_start();
    let (first, mut rest) = token(text)?;
    let schedule = if first.starts_with('@') {
        NICKNAMES.contains(&first).then(|| first.to_string())?
    } else {
        if !valid_field(first, 0) {
            return None;
        }
        for index in 1..5 {
            let (field, after) = token(rest)?;
            if !valid_field(field, index) {
                return None;
            }
            rest = after;
        }
        // The five fields are contiguous in the line, so they are normalised to single spaces.
        text[..text.len() - rest.len()].split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let user = if system {
        let (user, after) = token(rest)?;
        rest = after;
        Some(user)
    } else {
        None
    };
    (!rest.is_empty()).then_some((schedule, user, rest))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // BusyBox crond's `cron.update` lists the users whose crontab changed; it is not a crontab.
    if input.path.ends_with("crontabs/cron.update") {
        return Err(Error::skipped("crond's list of changed crontabs, not a crontab"));
    }
    // Solaris keeps audit information beside each crontab (`root.au`) and the daemon's own
    // control files in `etc/cron.d`; none of them is a crontab.
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let solaris_control = input.path.contains("etc/cron.d/")
        && matches!(name, "at.allow" | "at.deny" | "cron.allow" | "cron.deny" | "queuedefs" | "FIFO" | ".proto");
    if (input.path.contains("spool/cron/") && name.ends_with(".au")) || solaris_control {
        return Err(Error::skipped("Solaris cron audit or control file, not a crontab"));
    }
    let system = input.path.ends_with("etc/crontab") || input.path.contains("etc/cron.d/");
    let owner = (!system).then(|| input.path.rsplit('/').next().unwrap_or_default());
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let loc = Loc::Line(line.number);
        if let Some((name, value)) = env_assignment(text) {
            let entry =
                Entry { kind: "env", schedule: None, user: owner, command: None, name: Some(name), value: Some(value) };
            return sink.emit(loc, &entry);
        }
        let entry = match job(text, system) {
            Some((schedule, user, command)) => Entry {
                kind: "job",
                schedule: Some(schedule),
                user: user.or(owner),
                command: Some(command),
                name: None,
                value: None,
            },
            None => {
                sink.warn(format!("line {}: not a crontab entry", line.number));
                Entry { kind: "job", schedule: None, user: owner, command: Some(text), name: None, value: None }
            }
        };
        sink.emit(loc, &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn debian_system_crontab() {
        insta::assert_snapshot!(run(&CRON, "etc/crontab", &fixture("cron/crontab-debian"), 0));
    }

    #[test]
    fn cron_d_files() {
        insta::assert_snapshot!(run(&CRON, "etc/cron.d/anacron", &fixture("cron/cron.d-anacron"), 0));
        insta::assert_snapshot!(run(&CRON, "etc/cron.d/0hourly", &fixture("cron/cron.d-0hourly"), 0));
    }

    #[test]
    fn user_crontab_has_no_user_column() {
        insta::assert_snapshot!(run(&CRON, "var/spool/cron/crontabs/alice", &fixture("cron/user-crontab"), 0));
    }

    #[test]
    fn busybox_cron_update_is_not_a_crontab() {
        let out = run(&CRON, "etc/crontabs/cron.update", b"alice\n", 0);
        assert!(out.contains("skipped") && !out.contains("warning"), "{out}");
    }

    #[test]
    fn alpine_and_suse_user_crontabs_take_the_user_from_the_file_name() {
        use nixcavate_source::glob::Pattern;
        for path in ["etc/crontabs/root", "var/spool/cron/tabs/alice"] {
            assert!(CRON.paths.iter().any(|p| Pattern::new(p).matches(path)), "{path}");
            let out = run(&CRON, path, b"*/5 * * * * /tmp/x\n", 0);
            let user = path.rsplit('/').next().unwrap();
            assert!(out.contains(&format!("\"user\":\"{user}\"")), "{out}");
        }
    }

    #[test]
    fn every_documented_line_form() {
        insta::assert_snapshot!(run(&CRON, "etc/crontab", &fixture("cron/forms"), 0));
    }

    #[test]
    fn empty_and_garbage() {
        assert_eq!(run(&CRON, "etc/crontab", b"", 0), "");
        let _ = run(&CRON, "var/spool/cron/bob", b"\x00\xff\xfe\n= = =\n@\n* * * *\n\xc3\x28 x\n", 0);
    }

    /// Solaris keeps the prototype of an at job's script in `etc/cron.d/.proto`.
    #[test]
    fn the_solaris_at_job_prototype_is_not_a_crontab() {
        let out = run(&CRON, "etc/cron.d/.proto", b"#ident\ncd $d\numask $m\n$<\n", 0);
        assert!(out.contains("skipped") && !out.contains("warning"), "{out}");
    }

    #[test]
    fn scripts_report_file_metadata() {
        insta::assert_snapshot!(run(
            &SCRIPTS,
            "etc/cron.daily/apt-compat",
            &fixture("cron-scripts/apt-compat"),
            1_700_000_000
        ));
    }
}

//! MySQL and MariaDB logs: the error log, the general query log and the slow query log. Formats:
//! MySQL Reference Manual, "The Error Log" (MySQL 8 `2024-03-10T01:02:03.123456Z 0 [System]
//! [MY-010931] [Server] ...`; MySQL 5 and MariaDB `2024-03-10  1:02:03 0 [Note] ...`; the
//! `mysqld_safe` lines `240310 01:02:03 mysqld_safe ...`), "The General Query Log" (`Time Id
//! Command Argument` columns; the time is printed only when it changes in MariaDB) and "The Slow
//! Query Log" (`# Time:`, `# User@Host:`, `# Query_time:` header lines, `SET timestamp=...;`, the
//! statement).
//!
//! A time without a zone (MariaDB, `YYMMDD`) is the host's local time and is marked as an assumed
//! zone; MySQL 8 writes UTC with a `Z`. Statement text is shown as logged except that the literal
//! after `PASSWORD` or `IDENTIFIED BY` is replaced (MariaDB logs `CREATE USER ... IDENTIFIED BY
//! 'secret'` in clear; MySQL 8 already writes `<secret>`).

use crate::common::sql_redact::redact;
use crate::common::stamped_log::{parse as stamped, timestamp, Parsed};
use crate::common::syslog::timeline_message;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_iso8601, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ERROR_LOG: Artifact = Artifact::new(
    "mysql-error-log",
    "MySQL and MariaDB error log",
    Category::Logs,
    UNIX,
    &[
        "var/log/mysql/error.log*",
        "var/log/mysql/mysql.err*",
        "var/log/mysqld.log*",
        "var/log/mariadb/mariadb.log*",
        "var/log/mariadb/error.log*",
        "var/log/mysql.err*",
        "var/lib/mysql/*.err",
    ],
    |input, sink| stamped(input, sink, "a MySQL or MariaDB error log", "mysql_log", error_line),
);

pub const GENERAL_LOG: Artifact = Artifact::new(
    "mysql-general-log",
    "MySQL and MariaDB general query log: connections and statements",
    Category::Logs,
    UNIX,
    &[
        "var/log/mysql/mysql.log*",
        "var/log/mysql/general*.log*",
        "var/log/mariadb/general*.log*",
        "var/lib/mysql/general*.log*",
        "var/log/mysql/mysql-general.log*",
    ],
    parse_general,
);

pub const SLOW_LOG: Artifact = Artifact::new(
    "mysql-slow-log",
    "MySQL and MariaDB slow query log",
    Category::Logs,
    UNIX,
    &[
        "var/log/mysql/*slow*.log*",
        "var/log/mysql/mysql-slow*",
        "var/log/mariadb/*slow*.log*",
        "var/lib/mysql/*slow*.log*",
        "var/log/mysqld-slow.log*",
    ],
    parse_slow,
);

// ---- error log ----

/// `YYYY-MM-DD H:MM:SS` with a space-padded hour, as MariaDB and MySQL 5.6 write it.
fn padded_time(input: &Input, text: &str) -> Option<(Timestamp, usize)> {
    let b = text.as_bytes();
    let num =
        |range: std::ops::Range<usize>| parse_uint(b.get(range)?.trim_ascii()).and_then(|v| u32::try_from(v).ok());
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b' ')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let wall =
        secs_from_civil(i64::from(num(0..4)?), num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?)?;
    Some((input.local_time(wall, 0, Precision::Seconds), 19))
}

/// `240310 01:02:03 mysqld_safe ...` (two-digit year, no zone).
fn safe_time(input: &Input, text: &str) -> Option<(Timestamp, usize)> {
    let b = text.as_bytes();
    let num =
        |range: std::ops::Range<usize>| parse_uint(b.get(range)?.trim_ascii()).and_then(|v| u32::try_from(v).ok());
    if b.get(6) != Some(&b' ')
        || !b.get(..6)?.iter().all(u8::is_ascii_digit)
        || b.get(9) != Some(&b':')
        || b.get(12) != Some(&b':')
    {
        return None;
    }
    let wall =
        secs_from_civil(2000 + i64::from(num(0..2)?), num(2..4)?, num(4..6)?, num(7..9)?, num(10..12)?, num(13..15)?)?;
    Some((input.local_time(wall, 0, Precision::Seconds), 15))
}

fn error_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    if let Some((time, used)) = safe_time(input, line) {
        let rest = line.get(used..)?.trim_start();
        let (source, message) = rest.split_once(' ').unwrap_or((rest, ""));
        return Some(Parsed {
            time: Some(time),
            level: None,
            source: Some(source),
            pid: None,
            message,
            timeline: true,
        });
    }
    let (time, used) = match parse_iso8601(line.as_bytes()) {
        Some((parsed, used)) => (timestamp(input, &parsed), used),
        None => padded_time(input, line)?,
    };
    // `0 [System] [MY-010931] [Server] message` or `0 [Note] InnoDB: message`.
    let rest = line.get(used..)?.trim_start();
    let (thread, rest) = rest.split_once(' ')?;
    let pid = parse_uint(thread.as_bytes()).and_then(|p| u32::try_from(p).ok());
    let rest = rest.strip_prefix('[')?;
    let (level, rest) = rest.split_once("] ")?;
    // MySQL 8 follows the level with `[MY-code] [Subsystem]`; the message keeps both, as the
    // manual indexes messages by their code.
    let source = rest
        .strip_prefix("[MY-")
        .and_then(|_| rest.split_once("] ["))
        .and_then(|(_, subsystem)| subsystem.split_once(']'))
        .map(|(subsystem, _)| subsystem);
    Some(Parsed {
        time: Some(time),
        level: Some(level),
        source,
        pid,
        message: rest,
        timeline: matches!(level, "Warning" | "Error" | "System" | "ERROR" | "Critical"),
    })
}

// ---- general log ----

#[derive(Serialize)]
struct General<'a> {
    time: Option<Timestamp>,
    thread_id: Option<u64>,
    /// `Connect`, `Query`, `Quit`, `Init DB`, `Prepare`, `Execute`...
    command: &'a str,
    /// `db_connect` (a connection as a user; `db_login_failed` follows when it was refused),
    /// `db_login_failed`, `db_statement`, or empty.
    event: Option<&'static str>,
    user: Option<&'a str>,
    client_host: Option<&'a str>,
    database: Option<&'a str>,
    argument: Cow<'a, str>,
}

impl Record for General<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = format!("{}@{}", self.user.unwrap_or("?"), self.client_host.unwrap_or("?"));
        self.time
            .zip(self.event)
            .map(|(t, kind)| Event::new(t, kind, timeline_message(&who, &self.argument)))
            .into_iter()
    }
}

struct PendingGeneral {
    line: u64,
    time: Option<Timestamp>,
    thread: Option<u64>,
    command: String,
    argument: String,
}

/// `261113  1:25:08` (MariaDB) or `2026-11-13T01:25:32.082447Z` (MySQL 8).
fn general_time(input: &Input, text: &str) -> Option<Timestamp> {
    let text = text.trim();
    if let Some((parsed, _)) = parse_iso8601(text.as_bytes()) {
        return Some(timestamp(input, &parsed));
    }
    let (date, clock) = text.split_once(' ')?;
    let clock = clock.trim_start();
    let b = date.as_bytes();
    if b.len() != 6 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |s: &str| parse_uint(s.as_bytes()).and_then(|v| u32::try_from(v).ok());
    let mut c = clock.split(':');
    let (h, m, s) = (num(c.next()?)?, num(c.next()?)?, num(c.next()?)?);
    let wall = secs_from_civil(2000 + i64::from(num(&date[..2])?), num(&date[2..4])?, num(&date[4..6])?, h, m, s)?;
    Some(input.local_time(wall, 0, Precision::Seconds))
}

/// `[time]\t  id Command\targument`; the time is empty when it did not change.
fn general_entry(line: &str) -> Option<(&str, u64, &str, &str)> {
    let (left, rest) = line.split_once('\t')?;
    let rest = rest.trim_start_matches(['\t', ' ']);
    let (id, rest) = rest.split_once(' ')?;
    let id = parse_uint(id.as_bytes())?;
    let (command, argument) = rest.split_once('\t').unwrap_or((rest, ""));
    (!command.is_empty() && command.len() <= 16 && command.bytes().all(|b| b.is_ascii_alphabetic() || b == b' '))
        .then_some((left, id, command, argument))
}

fn parse_general(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut pending: Option<PendingGeneral> = None;
    let mut last_time: Option<Timestamp> = None;
    let mut seen = false;
    // Who each connection id is, so statements name their user.
    let mut threads: std::collections::HashMap<u64, (String, String)> = std::collections::HashMap::new();
    let mut flush = |pending: &mut Option<PendingGeneral>, sink: &mut Sink| -> Result<()> {
        let Some(entry) = pending.take() else { return Ok(()) };
        let argument = redact(&entry.argument);
        let (mut user, mut host, mut database, mut event) = (None, None, None, None);
        match entry.command.as_str() {
            "Connect" => {
                if argument.starts_with("Access denied") {
                    event = Some("db_login_failed");
                } else if let Some((identity, tail)) = argument.split_once(" on ") {
                    // `alice@localhost on appdb using Socket` (MariaDB adds `as anonymous`).
                    let (name, at) = identity.split_once('@').unwrap_or((identity, ""));
                    user = Some(name);
                    host = Some(at.split(' ').next().unwrap_or_default());
                    database = Some(tail.split(' ').next().unwrap_or_default()).filter(|d| !d.is_empty());
                    event = Some("db_connect");
                }
            }
            "Query" | "Execute" => event = Some("db_statement"),
            _ => {}
        }
        // Owned fields for the borrowed record.
        let (mut user, mut host, database) =
            (user.map(str::to_string), host.map(str::to_string), database.map(str::to_string));
        if let Some(thread) = entry.thread {
            match (event, entry.command.as_str()) {
                (Some("db_connect"), _) => {
                    if threads.len() >= 50_000 {
                        threads.clear();
                    }
                    threads.insert(thread, (user.clone().unwrap_or_default(), host.clone().unwrap_or_default()));
                }
                (_, "Quit") => {
                    threads.remove(&thread);
                }
                _ => {
                    if let Some((name, at)) = threads.get(&thread) {
                        user = user.or_else(|| Some(name.clone()));
                        host = host.or_else(|| Some(at.clone()));
                    }
                }
            }
        }
        let record = General {
            time: entry.time,
            thread_id: entry.thread,
            command: &entry.command,
            event,
            user: user.as_deref(),
            client_host: host.as_deref(),
            database: database.as_deref(),
            argument,
        };
        sink.emit(Loc::Line(entry.line), &record)
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() && pending.is_none() {
            return Ok(());
        }
        // The three header lines every file starts with.
        if !seen
            && pending.is_none()
            && (text.contains(", Version: ")
                || text.starts_with("Tcp port:")
                || (text.starts_with("Time") && text.contains("Command")))
        {
            return Ok(());
        }
        match general_entry(text) {
            Some((left, id, command, argument)) => {
                flush(&mut pending, sink)?;
                seen = true;
                if !left.trim().is_empty() {
                    last_time = general_time(input, left).or(last_time);
                }
                pending = Some(PendingGeneral {
                    line: line.number,
                    time: last_time,
                    thread: Some(id),
                    command: command.to_string(),
                    argument: argument.to_string(),
                });
            }
            None => match pending.as_mut() {
                Some(entry) if entry.argument.len() < (1 << 20) => {
                    entry.argument.push('\n');
                    entry.argument.push_str(text);
                }
                Some(_) => {}
                None => return Err(Error::format("not a MySQL general log: the first line is not an entry")),
            },
        }
        Ok(())
    })?;
    flush(&mut pending, sink)?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("no entries"))
    }
}

// ---- slow log ----

#[derive(Serialize, Default)]
struct Slow {
    time: Option<Timestamp>,
    user: Option<String>,
    client_host: Option<String>,
    thread_id: Option<u64>,
    database: Option<String>,
    query_seconds: Option<f64>,
    lock_seconds: Option<f64>,
    rows_sent: Option<u64>,
    rows_examined: Option<u64>,
    statement: String,
}

impl Record for Slow {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = format!("{}@{}", self.user.as_deref().unwrap_or("?"), self.client_host.as_deref().unwrap_or("?"));
        let message = format!("{:.3}s {}", self.query_seconds.unwrap_or(0.0), self.statement);
        self.time.map(|t| Event::new(t, "db_slow_query", timeline_message(&who, &message))).into_iter()
    }
}

/// The value after `key:` in a `# Query_time: 0.1  Lock_time: 0.0 ...` line.
fn stat<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(key)?;
    line.get(at + key.len()..)?.split_whitespace().next()
}

fn parse_slow(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut block: Option<(u64, Slow, bool)> = None;
    let mut header_time: Option<Timestamp> = None;
    let mut seen = false;
    let flush = |block: &mut Option<(u64, Slow, bool)>, sink: &mut Sink| -> Result<()> {
        if let Some((line, mut slow, _)) = block.take() {
            slow.statement = redact(slow.statement.trim()).into_owned();
            sink.emit(Loc::Line(line), &slow)?;
        }
        Ok(())
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if let Some(rest) = text.strip_prefix("# Time:") {
            flush(&mut block, sink)?;
            header_time = general_time(input, rest);
            return Ok(());
        }
        if let Some(rest) = text.strip_prefix("# User@Host:") {
            flush(&mut block, sink)?;
            seen = true;
            let rest = rest.trim();
            let (identity, id) = match rest.split_once("Id:") {
                Some((identity, id)) => (identity.trim(), parse_uint(id.trim().as_bytes())),
                None => (rest, None),
            };
            // `alice[alice] @ localhost [127.0.0.1]`
            let (user, host) = identity.split_once(" @ ").unwrap_or((identity, ""));
            let slow = Slow {
                time: header_time,
                user: Some(user.split('[').next().unwrap_or_default().to_string()),
                client_host: Some(host.trim().to_string()),
                thread_id: id,
                ..Slow::default()
            };
            block = Some((line.number, slow, false));
            return Ok(());
        }
        let Some((_, slow, in_statement)) = block.as_mut() else {
            // File headers (`/usr/sbin/mysqld, Version: ...`, `Tcp port:`, `Time Id Command`).
            return Ok(());
        };
        if !*in_statement && text.starts_with('#') {
            if let Some(id) = stat(text, "Thread_id:") {
                slow.thread_id = parse_uint(id.as_bytes());
                slow.database = text
                    .split("Schema:")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .filter(|d| *d != "QC_hit:")
                    .map(str::to_string);
            }
            if text.contains("Query_time:") {
                slow.query_seconds = stat(text, "Query_time:").and_then(|v| v.parse().ok());
                slow.lock_seconds = stat(text, "Lock_time:").and_then(|v| v.parse().ok());
                slow.rows_sent = stat(text, "Rows_sent:").and_then(|v| v.parse().ok());
                slow.rows_examined = stat(text, "Rows_examined:").and_then(|v| v.parse().ok());
            }
            return Ok(());
        }
        if let Some(epoch) = text.strip_prefix("SET timestamp=") {
            // Authoritative and zone-free: the epoch the server recorded.
            if let Some(secs) = parse_uint(epoch.trim_end_matches(';').as_bytes()).and_then(|s| i64::try_from(s).ok()) {
                slow.time = Some(Timestamp::from_secs(secs, Basis::Recorded));
            }
            *in_statement = true;
            return Ok(());
        }
        if let Some(db) = text.strip_prefix("use ").filter(|_| !*in_statement) {
            slow.database = Some(db.trim_end_matches(';').trim_matches('`').to_string());
            return Ok(());
        }
        *in_statement = true;
        if slow.statement.len() < (1 << 20) {
            if !slow.statement.is_empty() {
                slow.statement.push('\n');
            }
            slow.statement.push_str(text);
        }
        Ok(())
    })?;
    flush(&mut block, sink)?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("no slow query entries"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    fn clean(out: &str) {
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    fn lines_with(name: &str, needle: &str) -> usize {
        String::from_utf8_lossy(&fixture(name)).lines().filter(|l| l.contains(needle)).count()
    }

    /// Fixtures: real MariaDB 10.11.19 (Debian 12) and MySQL 8.4.13 (official image) with general and
    /// slow logs on, driven by their own clients: good logins, two bad passwords, an unknown user, a
    /// multi-line statement.
    #[test]
    fn general_logs_of_both_servers() {
        for name in ["mariadb", "mysql"] {
            let file = format!("svclogs/{name}/general.log");
            let out = run(&GENERAL_LOG, "var/log/mysql/mysql.log", &fixture(&file), 0);
            clean(&out);
            let connects = records(&out).iter().filter(|l| l.contains("\"command\":\"Connect\"")).count();
            assert_eq!(connects, lines_with(&file, "Connect\t"), "{name}");
            assert_eq!(
                out.matches("\"event\":\"db_login_failed\"").count(),
                lines_with(&file, "Access denied"),
                "{name}"
            );
            assert!(
                out.contains("\"user\":\"alice\",\"client_host\":\"") && out.contains("\"database\":\"appdb\"")
                    || name == "mysql",
                "{name}"
            );
            // The multi-line statement is one record.
            assert!(out.contains("SELECT 1,\\n  2"), "{name}: {out}");
            assert!(!out.contains("Example-Pass-1") && !out.contains("Example-Root-1"), "{name}");
        }
        let maria = run(&GENERAL_LOG, "var/log/mysql/mysql.log", &fixture("svclogs/mariadb/general.log"), 0);
        // The MariaDB log names the time only when it changes: later entries inherit it.
        assert!(maria.contains("\"time\":\"2026-11-13T01:28:"), "{maria}");
        assert!(maria.contains("IDENTIFIED BY '<redacted>'"), "{maria}");
        insta::assert_snapshot!(maria);
    }

    #[test]
    fn slow_logs_of_both_servers() {
        for name in ["mariadb", "mysql"] {
            let file = format!("svclogs/{name}/slow.log");
            let out = run(&SLOW_LOG, "var/log/mysql/mysql-slow.log", &fixture(&file), 0);
            clean(&out);
            assert_eq!(records(&out).len(), lines_with(&file, "# User@Host:"), "{name}");
            assert!(out.contains("\"user\":\"alice\""), "{name}");
            assert!(out.contains("SELECT sleep(0.2)"), "{name}");
            assert!(!out.contains("Example-Pass-1"), "{name}");
        }
        let out = run(&SLOW_LOG, "var/log/mysql/mysql-slow.log", &fixture("svclogs/mariadb/slow.log"), 0);
        // The slowest statement of the fixture is the `sleep(0.2)`.
        let sleeper = records(&out).into_iter().find(|l| l.contains("sleep(0.2)")).unwrap_or_default();
        assert!(sleeper.contains("\"database\":\"appdb\"") && sleeper.contains("\"query_seconds\":0.2"), "{sleeper}");
        assert!(out.contains("\"time\":\"2026-11-13T01:28:"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn error_logs_of_both_servers() {
        for (name, file, level) in [
            ("mysql", "error.log", "\"level\":\"System\",\"source\":\"Server\""),
            ("mariadb", "error.log", "\"level\":\"Note\""),
        ] {
            let data = fixture(&format!("svclogs/{name}/{file}"));
            let out = run(&ERROR_LOG, "var/log/mysql/error.log", &data, 0);
            clean(&out);
            assert_eq!(records(&out).len(), data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count(), "{name}");
            assert!(out.contains(level), "{name}");
        }
        let maria = run(&ERROR_LOG, "var/log/mysql/error.log", &fixture("svclogs/mariadb/error.log"), 0);
        assert!(maria.contains("mysqld_safe") && maria.contains("\"time\":\"2026-11-13T01:28:45Z\""), "{maria}");
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut seed = 31u64;
        for (artifact, name) in [
            (&GENERAL_LOG, "svclogs/mariadb/general.log"),
            (&GENERAL_LOG, "svclogs/mysql/general.log"),
            (&SLOW_LOG, "svclogs/mariadb/slow.log"),
            (&SLOW_LOG, "svclogs/mysql/slow.log"),
            (&ERROR_LOG, "svclogs/mariadb/error.log"),
        ] {
            let full = fixture(name);
            for cut in (0..full.len()).step_by(9) {
                run(artifact, "var/log/mysql/x.log", &full[..cut], 0);
            }
            for _ in 0..500 {
                let mut copy = full.clone();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, "var/log/mysql/x.log", &copy, 0);
            }
        }
    }
}

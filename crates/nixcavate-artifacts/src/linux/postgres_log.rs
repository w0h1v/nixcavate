//! PostgreSQL server logs: connections, failed logins, errors and (when `log_statement` is on)
//! statements. Formats: PostgreSQL documentation, "Error Reporting and Logging" (`stderr` with
//! `log_line_prefix`, `csvlog`, `jsonlog`).
//!
//! The `stderr` layout is read for the prefixes that start with a time (`%m` or `%t`) and a
//! `[%p]` process id, optionally followed by `%q%u@%d` (Debian's default, and the upstream
//! default without it). A line that starts with a tab or a space continues the entry before it
//! (a multi-line statement). `DETAIL`, `HINT` and `STATEMENT` lines are entries of their own, as
//! the server writes them. The CSV layout is read by its 22 to 26 columns, the JSON layout by
//! its key names. Which one a file is follows from its name (`.csv`, `.json`), compressed
//! rotations included.
//!
//! Statement text is shown as logged except that the literal after `PASSWORD` is replaced (see
//! `common::sql_redact`): `CREATE ROLE ... PASSWORD '...'` is logged in clear by the server.

use crate::common::sql_redact::redact;
use crate::common::stamped_log::timestamp;
use crate::common::syslog::timeline_message;
use crate::text::{decompressed, for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "postgres-log",
    "PostgreSQL server logs (stderr, csvlog, jsonlog)",
    Category::Logs,
    UNIX,
    &[
        "var/log/postgresql/*",
        "var/lib/pgsql/data/log/*",
        "var/lib/pgsql/*/data/log/*",
        "var/lib/postgresql/data/log/*",
        "var/lib/postgresql/*/main/log/*",
        "var/lib/postgresql/data/pg_log/*",
        "var/lib/pgsql/data/pg_log/*",
    ],
    parse,
);

/// Longest CSV record read; a quote that never closes cannot swallow the file.
const MAX_CSV_RECORD: usize = 1 << 20;
/// Connections whose client address is remembered between `connection received` and the entries
/// that follow with only a process id.
const MAX_PIDS: usize = 50_000;

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    pid: Option<u32>,
    user: Option<Cow<'a, str>>,
    database: Option<Cow<'a, str>>,
    level: &'a str,
    /// `db_login`, `db_login_failed`, `db_disconnect`, `db_statement` or `db_error`; empty for
    /// the rest (checkpoints, startup, parameters).
    event: Option<&'static str>,
    remote_host: Option<Cow<'a, str>>,
    application: Option<Cow<'a, str>>,
    sql_state: Option<Cow<'a, str>>,
    message: Cow<'a, str>,
    detail: Option<Cow<'a, str>>,
    hint: Option<Cow<'a, str>>,
    /// The statement that caused an error (`csvlog` `query`, `jsonlog` `statement`).
    statement: Option<Cow<'a, str>>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = format!("{}@{}", self.user.as_deref().unwrap_or("?"), self.database.as_deref().unwrap_or("?"));
        let message = || timeline_message(&who, &format!("{} {}", self.level, self.message));
        self.time.zip(self.event).map(|(t, kind)| Event::new(t, kind, message())).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let name = [".gz", ".zst", ".xz", ".bz2"].iter().find_map(|s| name.strip_suffix(s)).unwrap_or(name);
    if name.ends_with(".csv") {
        csv(input, sink)
    } else if name.ends_with(".json") {
        json(input, sink)
    } else {
        stderr(input, sink)
    }
}

/// The event class of an entry.
fn classify(level: &str, message: &str) -> Option<&'static str> {
    match level {
        "LOG" => {
            if message.starts_with("connection authorized:") {
                Some("db_login")
            } else if message.starts_with("disconnection:") {
                Some("db_disconnect")
            } else if message.starts_with("statement:")
                || message.starts_with("execute ")
                || (message.starts_with("duration: ") && message.contains(" statement: "))
            {
                Some("db_statement")
            } else {
                None
            }
        }
        "FATAL" if is_login_failure(message) => Some("db_login_failed"),
        "FATAL" | "ERROR" | "PANIC" => Some("db_error"),
        _ => None,
    }
}

fn is_login_failure(message: &str) -> bool {
    message.contains("authentication failed")
        || message.starts_with("no pg_hba.conf entry")
        || message.starts_with("password authentication")
        || message.contains("role \"") && message.ends_with("is not permitted to log in")
        || message.starts_with("database \"") && message.ends_with("does not exist")
}

/// `key=value` in a `connection authorized:` message.
fn pair<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    let at = message.find(key)?;
    if at != 0 && message.as_bytes().get(at - 1) != Some(&b' ') {
        return None;
    }
    let rest = message.get(at + key.len()..)?;
    Some(rest.split(' ').next().unwrap_or_default())
}

fn is_level(word: &str) -> bool {
    matches!(
        word,
        "LOG"
            | "INFO"
            | "NOTICE"
            | "WARNING"
            | "ERROR"
            | "FATAL"
            | "PANIC"
            | "DETAIL"
            | "HINT"
            | "STATEMENT"
            | "CONTEXT"
            | "QUERY"
            | "LOCATION"
    ) || word.strip_prefix("DEBUG").is_some_and(|n| matches!(n, "" | "1" | "2" | "3" | "4" | "5"))
}

/// `2024-03-10 01:02:03.123 UTC`, `... CET` or `... +01`: the zone name after the time.
fn log_time(input: &Input, text: &str) -> Option<(Timestamp, usize)> {
    let (parsed, used) = parse_iso8601(text.as_bytes())?;
    let rest = text.get(used..)?.strip_prefix(' ')?;
    let zone = rest.split(' ').next().unwrap_or_default();
    let mut total = used + 1 + zone.len();
    let offset = match zone {
        "UTC" | "GMT" | "Z" => Some(0),
        z if z.starts_with(['+', '-']) && z.len() >= 3 && z[1..].bytes().all(|b| b.is_ascii_digit() || b == b':') => {
            let digits: String = z[1..].chars().filter(char::is_ascii_digit).collect();
            let hours = parse_uint(digits.get(..2)?.as_bytes())? as i64;
            let minutes = digits.get(2..4).and_then(|m| parse_uint(m.as_bytes())).unwrap_or(0) as i64;
            let east = (hours * 3600 + minutes * 60) as i32;
            Some(if z.starts_with('-') { -east } else { east })
        }
        _ => None,
    };
    if offset.is_none() && !zone.bytes().all(|b| b.is_ascii_uppercase()) {
        // No zone at all (`log_line_prefix` without `%m`): the next word is not one.
        total = used;
    }
    let ts = match offset {
        Some(east) => {
            Timestamp::from_secs_nanos(parsed.secs - i64::from(east), parsed.nanos, parsed.precision, Basis::Recorded)
        }
        None => timestamp(input, &parsed),
    };
    Some((ts, total))
}

struct Pending {
    line: u64,
    time: Option<Timestamp>,
    pid: Option<u32>,
    user: String,
    database: String,
    level: String,
    message: String,
}

fn stderr(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut pending: Option<Pending> = None;
    let mut hosts: HashMap<u32, String> = HashMap::new();
    let mut seen = false;
    let result = for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        if text.starts_with(['\t', ' ']) {
            if let Some(entry) = pending.as_mut().filter(|e| e.message.len() < MAX_CSV_RECORD) {
                entry.message.push('\n');
                entry.message.push_str(text.trim_start_matches('\t'));
            }
            return Ok(());
        }
        let Some(entry) = split_line(input, text, line.number) else {
            if !seen {
                return Err(Error::format("not a PostgreSQL log: the first line starts no entry"));
            }
            sink.warn(format!("line {}: not a PostgreSQL log entry", line.number));
            return Ok(());
        };
        seen = true;
        if let Some(done) = pending.replace(entry) {
            flush(sink, done, &mut hosts)?;
        }
        Ok(())
    });
    if let Some(done) = pending {
        flush(sink, done, &mut hosts)?;
    }
    result?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

fn split_line(input: &Input, text: &str, number: u64) -> Option<Pending> {
    let (time, used) = log_time(input, text)?;
    let rest = text.get(used..)?.trim_start();
    // `[pid]` is in the default prefix since PostgreSQL 10 (`%m [%p] `); before, it was `%t `.
    let (pid, rest) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((pid, rest)) => (parse_uint(pid.as_bytes()).and_then(|p| u32::try_from(p).ok()), rest),
        None => (None, rest),
    };
    let (first, tail) = rest.split_once(' ')?;
    let (who, level, message) = match first.strip_suffix(':').filter(|l| is_level(l)) {
        Some(level) => (None, level, tail),
        None => {
            let (level, message) = tail.split_once(' ')?;
            (Some(first), level.strip_suffix(':').filter(|l| is_level(l))?, message)
        }
    };
    let (user, database) = who.and_then(|w| w.split_once('@')).unwrap_or(("", ""));
    // `%u@%d` before the connection is known.
    let known = |name: &str| if name == "[unknown]" { String::new() } else { name.to_string() };
    Some(Pending {
        line: number,
        time: Some(time),
        pid,
        user: known(user),
        database: known(database),
        level: level.to_string(),
        message: message.trim_start().to_string(),
    })
}

fn flush(sink: &mut Sink, entry: Pending, hosts: &mut HashMap<u32, String>) -> Result<()> {
    let message = redact(&entry.message);
    // `connection received: host=127.0.0.1 port=55860` names the client for the later entries
    // of that process, which only carry the process id.
    if let (Some(pid), Some(host)) =
        (entry.pid, message.strip_prefix("connection received: ").and_then(|m| pair(m, "host=")))
    {
        let port = message.split("port=").nth(1).map(|p| p.split(' ').next().unwrap_or_default());
        if hosts.len() >= MAX_PIDS {
            hosts.clear();
        }
        hosts.insert(pid, port.map_or_else(|| host.to_string(), |p| format!("{host}:{p}")));
    }
    let remote = entry.pid.and_then(|p| hosts.get(&p)).cloned();
    if message.starts_with("disconnection:") {
        if let Some(pid) = entry.pid {
            hosts.remove(&pid);
        }
    }
    let authorized = message.strip_prefix("connection authorized: ");
    let user =
        authorized.and_then(|m| pair(m, "user=")).map(str::to_string).or(Some(entry.user).filter(|u| !u.is_empty()));
    let database = authorized
        .and_then(|m| pair(m, "database="))
        .map(str::to_string)
        .or(Some(entry.database).filter(|d| !d.is_empty()));
    let record = Entry {
        time: entry.time,
        pid: entry.pid,
        user: user.map(Cow::Owned),
        database: database.map(Cow::Owned),
        level: &entry.level,
        event: classify(&entry.level, &message),
        remote_host: remote.map(Cow::Owned),
        application: authorized.and_then(|m| pair(m, "application_name=")).map(|a| Cow::Owned(a.to_string())),
        sql_state: None,
        message,
        detail: None,
        hint: None,
        statement: None,
    };
    sink.emit(Loc::Line(entry.line), &record)
}

// ---- csvlog ----

/// Reads one CSV record at `*pos`: `"` quotes a field and may span lines, `""` is a quote.
fn csv_record<'a>(data: &'a [u8], pos: &mut usize, fields: &mut Vec<Cow<'a, [u8]>>) -> Option<bool> {
    fields.clear();
    let start = *pos;
    let mut i = start;
    loop {
        if i.saturating_sub(start) > MAX_CSV_RECORD {
            return None;
        }
        if data.get(i) == Some(&b'"') {
            let mut j = i + 1;
            let mut escaped = false;
            loop {
                let at = memchr::memchr(b'"', data.get(j..)?)? + j;
                if data.get(at + 1) == Some(&b'"') {
                    escaped = true;
                    j = at + 2;
                } else {
                    j = at;
                    break;
                }
            }
            let raw = data.get(i + 1..j)?;
            fields.push(if escaped { Cow::Owned(unescape(raw)) } else { Cow::Borrowed(raw) });
            i = j + 1;
        } else {
            let end = data.get(i..)?.iter().position(|&b| b == b',' || b == b'\n').map_or(data.len(), |p| i + p);
            fields.push(Cow::Borrowed(data.get(i..end)?));
            i = end;
        }
        match data.get(i) {
            Some(b',') => i += 1,
            Some(b'\r') if data.get(i + 1) == Some(&b'\n') => {
                *pos = i + 2;
                return Some(true);
            }
            Some(b'\n') => {
                *pos = i + 1;
                return Some(true);
            }
            None => {
                *pos = i;
                return Some(true);
            }
            Some(_) => return None,
        }
    }
}

fn unescape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        out.push(raw[i]);
        i += if raw[i] == b'"' { 2 } else { 1 };
    }
    out
}

fn csv(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    let mut pos = 0;
    let mut fields = Vec::new();
    let mut number = 0u64;
    while pos < data.len() {
        let start_line = number + 1;
        let before = pos;
        if csv_record(&data, &mut pos, &mut fields).is_none() {
            return Err(Error::format(format!(
                "line {start_line}: a quoted field is not closed or the record is longer than {MAX_CSV_RECORD} bytes"
            )));
        }
        number += data.get(before..pos).map_or(1, |b| b.iter().filter(|&&c| c == b'\n').count() as u64).max(1);
        if fields.len() == 1 && fields[0].is_empty() {
            continue;
        }
        if !(22..=26).contains(&fields.len()) {
            sink.warn(format!("line {start_line}: {} columns, expected 22 to 26 (csvlog)", fields.len()));
            continue;
        }
        let text =
            |i: usize| -> Option<String> { fields.get(i).map(|f| lossy(f).into_owned()).filter(|s| !s.is_empty()) };
        let level = text(11).unwrap_or_default();
        let message = text(13).unwrap_or_default();
        let message = redact(&message).into_owned();
        let time = text(0).and_then(|t| log_time(input, &t)).map(|(ts, _)| ts);
        if text(0).is_some() && time.is_none() {
            sink.warn(format!("line {start_line}: unreadable time"));
        }
        let record = Entry {
            time,
            pid: text(3).and_then(|p| parse_uint(p.as_bytes())).and_then(|p| u32::try_from(p).ok()),
            user: text(1).map(Cow::Owned),
            database: text(2).map(Cow::Owned),
            level: &level,
            event: classify(&level, &message),
            remote_host: text(4).map(Cow::Owned),
            application: text(22).map(Cow::Owned),
            sql_state: text(12).map(Cow::Owned),
            message: Cow::Owned(message),
            detail: text(14).map(|d| Cow::Owned(redact(&d).into_owned())),
            hint: text(15).map(Cow::Owned),
            statement: text(19).map(|q| Cow::Owned(redact(&q).into_owned())),
        };
        sink.emit(Loc::Line(start_line), &record)?;
    }
    if number == 0 {
        Err(Error::skipped("empty file"))
    } else {
        Ok(())
    }
}

// ---- jsonlog ----

#[derive(Deserialize)]
struct JsonEntry<'a> {
    #[serde(borrow)]
    timestamp: Option<Cow<'a, str>>,
    #[serde(borrow)]
    user: Option<Cow<'a, str>>,
    #[serde(borrow)]
    dbname: Option<Cow<'a, str>>,
    pid: Option<u32>,
    #[serde(borrow)]
    remote_host: Option<Cow<'a, str>>,
    remote_port: Option<u32>,
    #[serde(borrow)]
    error_severity: Option<Cow<'a, str>>,
    #[serde(borrow)]
    state_code: Option<Cow<'a, str>>,
    #[serde(borrow)]
    message: Option<Cow<'a, str>>,
    #[serde(borrow)]
    detail: Option<Cow<'a, str>>,
    #[serde(borrow)]
    hint: Option<Cow<'a, str>>,
    #[serde(borrow)]
    statement: Option<Cow<'a, str>>,
    #[serde(borrow)]
    application_name: Option<Cow<'a, str>>,
}

fn json(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen = false;
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let Ok(entry) = serde_json::from_slice::<JsonEntry>(line.bytes) else {
            if !seen {
                return Err(Error::format("not a PostgreSQL jsonlog: the first line is not a JSON object"));
            }
            sink.warn(format!("line {}: not a JSON log entry", line.number));
            return Ok(());
        };
        seen = true;
        let level = entry.error_severity.as_deref().unwrap_or_default();
        let message = redact(entry.message.as_deref().unwrap_or_default()).into_owned();
        let remote = entry.remote_host.as_deref().map(|h| match entry.remote_port {
            Some(port) => Cow::Owned(format!("{h}:{port}")),
            None => Cow::Borrowed(h),
        });
        let record = Entry {
            time: entry.timestamp.as_deref().and_then(|t| log_time(input, t)).map(|(ts, _)| ts),
            pid: entry.pid,
            user: entry.user.clone().filter(|u| !u.is_empty()),
            database: entry.dbname.clone().filter(|d| !d.is_empty()),
            level,
            event: classify(level, &message),
            remote_host: remote,
            application: entry.application_name.clone().filter(|a| !a.is_empty()),
            sql_state: entry.state_code.clone(),
            message: Cow::Owned(message),
            detail: entry.detail.as_deref().map(|d| Cow::Owned(redact(d).into_owned())),
            hint: entry.hint.clone(),
            statement: entry.statement.as_deref().map(|s| Cow::Owned(redact(s).into_owned())),
        };
        sink.emit(Loc::Line(line.number), &record)
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    fn count(out: &str, event: &str) -> usize {
        records(out).iter().filter(|l| l.contains(&format!("\"event\":\"{event}\""))).count()
    }

    fn all(name: &str) -> [String; 3] {
        let one = |ext: &str| {
            run(
                &ARTIFACT,
                &format!("var/log/postgresql/{name}.{ext}"),
                &fixture(&format!("svclogs/postgres/{name}.{ext}")),
                0,
            )
        };
        [one("log"), one("csv"), one("json")]
    }

    /// Fixture: real PostgreSQL 15.19 (Debian 12) with `log_destination = stderr,csvlog,jsonlog`,
    /// driven by psql: 11 logins, 4 failed logins (2 bad passwords, 2 unknown role) and one missing database.
    #[test]
    fn the_three_formats_agree() {
        for name in ["pg-01", "plain-01"] {
            let [text, csv, json] = all(name);
            for out in [&text, &csv, &json] {
                assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{name}: {out}");
            }
            // The independent counts: csv rows through Python's csv module (88 and 76), json lines, and
            // text lines that start an entry.
            let entries = |ext: &str| {
                String::from_utf8_lossy(&fixture(&format!("svclogs/postgres/{name}.{ext}")))
                    .lines()
                    .filter(|l| !l.starts_with(['\t', ' ']))
                    .count()
            };
            assert_eq!(records(&text).len(), entries("log"), "{name} text");
            assert_eq!(records(&json).len(), entries("json"), "{name} json");
            assert_eq!(records(&csv).len(), if name == "pg-01" { 88 } else { 76 }, "{name} csv");
            // The text log writes DETAIL, HINT and STATEMENT as entries of their own; csvlog and
            // jsonlog keep them as columns of the entry they belong to.
            let extra = records(&text)
                .iter()
                .filter(|l| {
                    ["DETAIL", "HINT", "STATEMENT", "CONTEXT", "QUERY"]
                        .iter()
                        .any(|k| l.contains(&format!("\"level\":\"{k}\"")))
                })
                .count();
            assert_eq!(records(&text).len() - extra, records(&csv).len(), "{name}");
            for event in ["db_login", "db_login_failed", "db_disconnect", "db_statement", "db_error"] {
                assert_eq!(count(&text, event), count(&csv, event), "{name} {event} text/csv");
                assert_eq!(count(&text, event), count(&json, event), "{name} {event} text/json");
            }
            assert_eq!(count(&text, "db_login_failed"), 5, "{name}: 4 failed logins and the missing database");
        }
    }

    #[test]
    fn multi_line_statements_are_joined_and_secrets_are_not_shown() {
        for out in all("pg-01") {
            assert!(out.contains("SELECT id,\\n     name\\n   FROM t\\n  WHERE id = 1"), "{out}");
            assert!(out.contains("PASSWORD '<redacted>'"), "{out}");
            assert!(!out.contains("Example-Pass-1"), "{out}");
        }
    }

    #[test]
    fn failed_logins_name_the_client_and_the_debian_prefix_gives_user_and_database() {
        let out = run(&ARTIFACT, "var/log/postgresql/pg-01.log", &fixture("svclogs/postgres/pg-01.log"), 0);
        let failed = records(&out)
            .into_iter()
            .find(|l| l.contains("db_login_failed") && l.contains("nosuchuser"))
            .unwrap_or_default();
        assert!(
            failed.contains("\"remote_host\":\"127.0.0.1:") && failed.contains("\"database\":\"appdb\""),
            "{failed}"
        );
        let plain = run(&ARTIFACT, "var/log/postgresql/plain-01.log", &fixture("svclogs/postgres/plain-01.log"), 0);
        assert!(plain.contains("\"user\":\"alice\",\"database\":\"appdb\""), "login lines still carry them");
        insta::assert_snapshot!(out);
    }

    /// Before PostgreSQL 10 the default `log_line_prefix` was `%t `: no process id.
    #[test]
    fn the_old_default_prefix_has_no_process_id() {
        let log = b"2016-04-25 21:02:32 CEST LOG:  database system is ready to accept connections\n\
2016-04-25 21:02:32 CEST LOG:  incomplete startup packet\n\
2016-04-25 21:08:52 UTC FATAL:  password authentication failed for user \"bob\"\n";
        let out = run(&ARTIFACT, "var/log/postgresql/postgresql-9.3-main.log", log, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), 3, "{out}");
        assert!(out.contains(r#""level":"LOG","#) && out.contains("database system is ready"), "{out}");
        assert!(out.contains(r#""time":"2016-04-25T21:08:52Z""#), "{out}");
    }

    #[test]
    fn times_state_their_zone() {
        let out = run(&ARTIFACT, "var/log/postgresql/x.log", b"2024-03-10 01:02:03.123 UTC [5] LOG:  hello\n2024-03-10 01:02:03 +01 [5] LOG:  hi\n2024-03-10 01:02:03 CET [5] ERROR:  x\n", 0);
        assert!(
            out.contains("\"time\":\"2024-03-10T01:02:03.123Z\"") && out.contains("\"time\":\"2024-03-10T00:02:03Z\""),
            "{out}"
        );
        assert!(out.contains("assumed_zone"), "{out}");
    }

    #[test]
    fn other_files_and_empty_files_are_refused() {
        assert!(run(&ARTIFACT, "var/log/postgresql/x.log", b"just text\n", 0).contains("not a PostgreSQL log"));
        assert!(run(&ARTIFACT, "var/log/postgresql/x.log", b"", 0).contains("skipped"));
        assert!(run(&ARTIFACT, "var/log/postgresql/x.json", b"[1,2]\n", 0).contains("not a PostgreSQL jsonlog"));
        assert!(run(&ARTIFACT, "var/log/postgresql/x.csv", b"1,\"2\n", 0).contains("not closed"));
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for (name, ext) in [("pg-01", "log"), ("pg-01", "csv"), ("pg-01", "json")] {
            let full = fixture(&format!("svclogs/postgres/{name}.{ext}"));
            let path = format!("var/log/postgresql/{name}.{ext}");
            for cut in (0..full.len().min(6000)).step_by(29) {
                run(&ARTIFACT, &path, &full[..cut], 0);
            }
            for _ in 0..1500 {
                let mut copy = full[..2500.min(full.len())].to_vec();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(&ARTIFACT, &path, &copy, 0);
            }
        }
    }
}

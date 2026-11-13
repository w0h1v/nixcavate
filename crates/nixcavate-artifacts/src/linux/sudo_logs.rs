//! sudo's own evidence, one artifact per file family:
//!
//! * `sudo-io`: I/O log sessions under `var/log/sudo-io/**` (`iolog_dir`), one directory per
//!   session. Input is the session's `log.json` (sudo 1.9) or `log` (three-line text: `time:
//!   user:runas user:runas group:tty[:lines:columns]`, the working directory, the command).
//!   The `timing` file beside it (plain or compressed) gives the session's length and how many
//!   bytes each stream carried; the streams themselves (`ttyin`, `ttyout`, `stdin`, `stdout`,
//!   `stderr`) are never read: they can hold passwords and terminal control sequences. When a
//!   directory has both `log.json` and `log`, the JSON one is used.
//! * `sudo-log`: the log file `Defaults logfile=` writes: classic text (`Nov 13 02:32:54 : alice :
//!   TTY=pts/0 ; PWD=/ ; USER=bob ; COMMAND=...`, wrapped at 80 columns with indented
//!   continuation lines) or `log_format=json` events.
//! * `sudo-timestamps`: the authentication cache `ts/<user>` (the file's modification time is the
//!   user's last authentication) and `sudo-lectured`: the empty files whose presence says the
//!   user has been shown the sudo lecture.
//!
//! Formats: sudoers(5), sudo_logsrvd protocol / sudoreplay(8) and `sudo_json` as written by 1.8
//! and 1.9; the fixtures come from sudo 1.8.23 and 1.9.x run for real.

use super::passwd_lookup;
use crate::common::year::utc_without_year;
use crate::text::{decompressed, for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const IOLOG: Artifact = Artifact::new(
    "sudo-io",
    "sudo I/O log sessions (who ran what, when, for how long)",
    Category::Execution,
    LINUX,
    &["var/log/sudo-io/**/log", "var/log/sudo-io/**/log.json"],
    parse_iolog,
);

pub const LOG: Artifact = Artifact::new(
    "sudo-log",
    "sudo log file (classic or JSON)",
    Category::Execution,
    LINUX,
    &["var/log/sudo.log*", "var/log/sudo/sudo.log*", "var/log/sudo.json*", "var/log/sudo/sudo.json*"],
    parse_log,
);

pub const TIMESTAMPS: Artifact = Artifact::new(
    "sudo-timestamps",
    "sudo authentication cache (last sudo authentication per user)",
    Category::Execution,
    LINUX,
    &["var/db/sudo/ts/*", "var/lib/sudo/ts/*", "run/sudo/ts/*", "var/run/sudo/ts/*", "var/db/sudo/*", "var/lib/sudo/*"],
    parse_timestamps,
);

pub const LECTURED: Artifact = Artifact::new(
    "sudo-lectured",
    "Users who have been shown the sudo lecture",
    Category::Execution,
    LINUX,
    &["var/db/sudo/lectured/*", "var/lib/sudo/lectured/*"],
    parse_lectured,
)
.presence();

const MAX_JSON: usize = 1 << 20;

// ---- sudo-io ----

#[derive(Serialize)]
struct Session<'a> {
    /// The session directory (the `TSID`, the sequence number sudoreplay lists).
    session: &'a str,
    time: Option<Timestamp>,
    user: String,
    run_user: String,
    run_group: String,
    tty: String,
    cwd: String,
    command: String,
    /// The machine the command was submitted on (sudo 1.9 only).
    submit_host: String,
    lines: Option<u64>,
    columns: Option<u64>,
    /// The sum of the delays in `timing`; None when there is no readable timing file.
    duration_seconds: Option<f64>,
    stdin_bytes: Option<u64>,
    stdout_bytes: Option<u64>,
    stderr_bytes: Option<u64>,
    tty_in_bytes: Option<u64>,
    tty_out_bytes: Option<u64>,
    log_format: &'static str,
}

impl Record for Session<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let for_whom = if self.run_user.is_empty() { String::new() } else { format!(" as {}", self.run_user) };
        let ran = self.duration_seconds.map(|d| format!(" for {d:.1} s")).unwrap_or_default();
        let message = format!("{} ran {}{for_whom} through sudo (I/O logged{ran})", self.user, self.command);
        self.time.map(|ts| Event::new(ts, "executed", message)).into_iter()
    }
}

/// The metadata of one session, from either log form.
struct Meta {
    time: Option<Timestamp>,
    user: String,
    run_user: String,
    run_group: String,
    tty: String,
    cwd: String,
    command: String,
    host: String,
    lines: Option<u64>,
    columns: Option<u64>,
    format: &'static str,
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn parse_log_json(data: &[u8]) -> Option<Meta> {
    let value: Value = serde_json::from_slice(data.get(..MAX_JSON).unwrap_or(data)).ok()?;
    let argv: Vec<&str> = value.get("runargv")?.as_array()?.iter().filter_map(Value::as_str).collect();
    let stamp = value.get("timestamp");
    let secs = stamp.and_then(|t| t.get("seconds")).and_then(Value::as_i64);
    let nanos = stamp.and_then(|t| t.get("nanoseconds")).and_then(Value::as_u64).unwrap_or(0);
    Some(Meta {
        time: secs.and_then(|s| Timestamp::checked(s, u32::try_from(nanos).ok()?, Precision::Nanos, Basis::Recorded)),
        user: text(&value, "submituser"),
        run_user: text(&value, "runuser"),
        run_group: text(&value, "rungroup"),
        tty: text(&value, "ttyname"),
        cwd: text(&value, "submitcwd"),
        // sudo logs the command and its arguments in `runargv`; `command` is the resolved path.
        command: if argv.is_empty() { text(&value, "command") } else { argv.join(" ") },
        host: text(&value, "submithost"),
        lines: value.get("lines").and_then(Value::as_u64),
        columns: value.get("columns").and_then(Value::as_u64),
        format: "json",
    })
}

fn parse_log_legacy(data: &[u8]) -> Option<Meta> {
    let mut lines = data.split(|&b| b == b'\n');
    let first = lossy(lines.next()?).into_owned();
    let cwd = lossy(lines.next()?).into_owned();
    let command = lossy(lines.next()?).into_owned();
    let mut f = first.split(':');
    let secs = parse_uint(f.next()?.as_bytes()).and_then(|s| i64::try_from(s).ok())?;
    let (user, run_user, run_group, tty) = (f.next()?, f.next()?, f.next()?, f.next()?);
    let (rows, cols) = (f.next().and_then(|v| v.parse().ok()), f.next().and_then(|v| v.parse().ok()));
    Some(Meta {
        time: Timestamp::checked(secs, 0, Precision::Seconds, Basis::Recorded),
        user: user.to_string(),
        run_user: run_user.to_string(),
        run_group: run_group.to_string(),
        tty: tty.to_string(),
        cwd,
        command,
        host: String::new(),
        lines: rows,
        columns: cols,
        format: "legacy",
    })
}

/// Totals from `timing`: lines are `<event> <delay> <bytes>` (0 stdin, 1 stdout, 2 stderr, 3 ttyin,
/// 4 ttyout) or, for window changes and suspends, other arguments. Returns the length, the bytes
/// per stream and how many lines were not understood.
fn totals(timing: &[u8]) -> (f64, [u64; 5], usize) {
    let (mut seconds, mut bytes, mut bad) = (0f64, [0u64; 5], 0usize);
    for line in timing.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let text = lossy(line);
        let mut f = text.split_whitespace();
        let (Some(kind), Some(delay)) =
            (f.next().and_then(|k| k.parse::<usize>().ok()), f.next().and_then(|d| d.parse::<f64>().ok()))
        else {
            bad += 1;
            continue;
        };
        if !(delay.is_finite() && delay >= 0.0) {
            bad += 1;
            continue;
        }
        seconds += delay;
        if let Some(slot) = bytes.get_mut(kind) {
            match f.next().and_then(|n| n.parse::<u64>().ok()) {
                Some(n) => *slot = slot.saturating_add(n),
                None => bad += 1,
            }
        }
    }
    ((seconds * 1e6).round() / 1e6, bytes, bad)
}

fn parse_iolog(input: &Input, sink: &mut Sink) -> Result<()> {
    let (dir, name) = input.path.rsplit_once('/').unwrap_or(("", input.path));
    if name == "log" && input.host.entry(&format!("{dir}/log.json")).is_some() {
        return Err(Error::skipped("log.json in the same session is read instead"));
    }
    let meta = if name == "log.json" { parse_log_json(input.data) } else { parse_log_legacy(input.data) }
        .ok_or_else(|| Error::format(format!("{name} is not a sudo I/O session log")))?;
    let timing = input.host.read(&format!("{dir}/timing")).and_then(|t| decompressed(&t).map(|c| c.into_owned()).ok());
    let (seconds, bytes) = match &timing {
        Some(t) => {
            let (seconds, bytes, bad) = totals(t);
            if bad > 0 {
                sink.warn(format!("{bad} timing lines not understood: durations and byte counts may be short"));
            }
            (Some(seconds), Some(bytes))
        }
        None => {
            sink.warn(format!("{dir}/timing is missing or unreadable: no duration or byte counts"));
            (None, None)
        }
    };
    let at = |i: usize| bytes.map(|b| b[i]);
    sink.emit(
        Loc::None,
        &Session {
            session: dir.strip_prefix("var/log/sudo-io/").unwrap_or(dir),
            time: meta.time,
            user: meta.user,
            run_user: meta.run_user,
            run_group: meta.run_group,
            tty: meta.tty,
            cwd: meta.cwd,
            command: meta.command,
            submit_host: meta.host,
            lines: meta.lines,
            columns: meta.columns,
            duration_seconds: seconds,
            stdin_bytes: at(0),
            stdout_bytes: at(1),
            stderr_bytes: at(2),
            tty_in_bytes: at(3),
            tty_out_bytes: at(4),
            log_format: meta.format,
        },
    )
}

// ---- sudo-log ----

#[derive(Serialize)]
struct LogEntry {
    time: Option<Timestamp>,
    time_basis: Basis,
    /// `classic` or `json`.
    format: &'static str,
    /// JSON events: `accept`, `reject`, `exit` or `alert`. Classic lines: empty.
    event: String,
    user: String,
    /// The free text: `command not allowed`, `3 incorrect password attempts`, a reason. Empty
    /// for a command that was allowed.
    message: String,
    run_user: String,
    run_group: String,
    tty: String,
    cwd: String,
    submit_host: String,
    command: String,
    /// The sudo session's sequence number, which names its I/O log directory.
    tsid: String,
    uuid: String,
    exit_value: Option<i64>,
}

impl Record for LogEntry {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = format!("{} as {}", self.user, if self.run_user.is_empty() { "root" } else { &self.run_user });
        let lower = self.message.to_ascii_lowercase();
        let denied =
            matches!(self.event.as_str(), "reject" | "alert") || (!self.message.is_empty() && self.event != "exit");
        let (kind, message) = if lower.contains("incorrect password") {
            ("failed_login", format!("sudo: {} ({who}): {}", self.user, self.message))
        } else if denied {
            ("sudo_denied", format!("sudo refused {who}: {} {}", self.message, self.command))
        } else if self.event == "exit" {
            ("sudo_exit", format!("sudo command of {who} exited with {}", self.exit_value.unwrap_or(-1)))
        } else {
            ("executed", format!("{who} ran {} through sudo", self.command))
        };
        self.time.map(|ts| Event::new(ts, kind, message)).into_iter()
    }
}

/// `Nov 13 02:32:54` or `Nov 13 02:32:54 2026` (with `log_year`): the part of a classic line
/// before the first ` : `, as wall-clock seconds with the year the file's age implies when
/// there is none.
fn classic_time(input: &Input, stamp: &str) -> Option<(Timestamp, Basis)> {
    let t: Vec<&str> = stamp.split_whitespace().collect();
    let month = nixcavate_core::time::month_from_abbrev(t.first()?.as_bytes())?;
    let day: u32 = t.get(1)?.parse().ok()?;
    let mut hms = t.get(2)?.split(':').map(|v| v.parse::<u32>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    match t.get(3).and_then(|y| y.parse::<i64>().ok()) {
        Some(year) => {
            let wall = nixcavate_core::time::secs_from_civil(year, month, day, h, m, s)?;
            Some((input.local_time(wall, 0, Precision::Seconds), Basis::AssumedZone))
        }
        None => {
            let secs = utc_without_year(month, day, h, m, s, input.mtime, &input.host.tz)?;
            Some((Timestamp::from_secs(secs, Basis::InferredYearAssumedZone), Basis::InferredYearAssumedZone))
        }
    }
}

fn classic_entry(input: &Input, line: &str) -> Option<LogEntry> {
    let (stamp, rest) = line.split_once(" : ")?;
    let (time, basis) = match classic_time(input, stamp) {
        Some((t, b)) => (Some(t), b),
        None => (None, Basis::InferredYearAssumedZone),
    };
    let (user, details) = rest.split_once(" : ")?;
    let mut entry = LogEntry {
        time,
        time_basis: basis,
        format: "classic",
        event: String::new(),
        user: user.to_string(),
        message: String::new(),
        run_user: String::new(),
        run_group: String::new(),
        tty: String::new(),
        cwd: String::new(),
        submit_host: String::new(),
        command: String::new(),
        tsid: String::new(),
        uuid: String::new(),
        exit_value: None,
    };
    let mut parts = details.split(" ; ").peekable();
    let mut free = Vec::new();
    while let Some(part) = parts.next() {
        let part = part.trim_end_matches(" ;").trim_end_matches(';').trim();
        match part.split_once('=') {
            Some(("COMMAND", first)) => {
                // The command takes the rest of the line, ` ; ` inside it included.
                let mut command = first.to_string();
                for more in parts.by_ref() {
                    command.push_str(" ; ");
                    command.push_str(more);
                }
                entry.command = command;
            }
            Some(("TTY", v)) => entry.tty = v.to_string(),
            Some(("PWD", v)) => entry.cwd = v.to_string(),
            Some(("USER", v)) => entry.run_user = v.to_string(),
            Some(("GROUP", v)) => entry.run_group = v.to_string(),
            Some(("HOST", v)) => entry.submit_host = v.to_string(),
            Some(("TSID", v)) => entry.tsid = v.to_string(),
            Some((key, _)) if key.chars().all(|c| c.is_ascii_uppercase()) && !key.is_empty() => {} // ENV and the like
            _ if !part.is_empty() => free.push(part),
            _ => {}
        }
    }
    entry.message = free.join("; ");
    Some(entry)
}

/// The event kinds sudo's JSON log writes.
const EVENTS: [&str; 5] = ["accept", "reject", "exit", "alert", "command"];

fn json_entry(event: &str, body: &Value) -> Option<LogEntry> {
    if !body.is_object() || !EVENTS.contains(&event) {
        return None;
    }
    let time = ["server_time", "submit_time"].iter().find_map(|k| body.get(*k)).and_then(|t| {
        let secs = t.get("seconds")?.as_i64()?;
        let nanos = u32::try_from(t.get("nanoseconds").and_then(Value::as_u64).unwrap_or(0)).ok()?;
        Timestamp::checked(secs, nanos, Precision::Nanos, Basis::Recorded)
    });
    let argv: Vec<&str> = body
        .get("runargv")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    Some(LogEntry {
        time,
        time_basis: Basis::Recorded,
        format: "json",
        event: event.to_string(),
        user: text(body, "submituser"),
        message: ["reason", "error"].iter().map(|k| text(body, k)).find(|v| !v.is_empty()).unwrap_or_default(),
        run_user: text(body, "runuser"),
        run_group: text(body, "rungroup"),
        tty: text(body, "ttyname"),
        cwd: text(body, "submitcwd"),
        submit_host: text(body, "submithost"),
        command: if argv.is_empty() { text(body, "command") } else { argv.join(" ") },
        tsid: String::new(),
        uuid: text(body, "uuid"),
        exit_value: body.get("exit_value").and_then(Value::as_i64),
    })
}

/// Splits a file of concatenated top-level JSON objects (the JSON log writes them one after
/// another, pretty-printed), tracking strings so braces inside them do not count.
fn json_objects(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let (mut depth, mut start, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    let mut at = 0usize;
    std::iter::from_fn(move || {
        while let Some(&b) = data.get(at) {
            at += 1;
            if in_string {
                match (escaped, b) {
                    (true, _) => escaped = false,
                    (false, b'\\') => escaped = true,
                    (false, b'"') => in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                b'{' => {
                    if depth == 0 {
                        start = at - 1;
                    }
                    depth += 1;
                }
                b'}' if depth > 0 => {
                    depth -= 1;
                    if depth == 0 {
                        return data.get(start..at);
                    }
                }
                _ => {}
            }
        }
        None
    })
}

/// The `"key": {...}` members of one top-level object. The log is one object whose keys repeat
/// (`accept`, `accept`, `reject`...: sudo appends events to it), which a JSON parser would
/// collapse into the last one; so the members are split here and parsed one by one.
fn members(object: &[u8]) -> Vec<(&str, &[u8])> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < object.len() {
        while object.get(i).is_some_and(|b| b.is_ascii_whitespace() || *b == b',') {
            i += 1;
        }
        if object.get(i) != Some(&b'"') {
            break;
        }
        let key_start = i + 1;
        i = key_start;
        while object.get(i).is_some_and(|&b| b != b'"') {
            i += if object[i] == b'\\' { 2 } else { 1 };
        }
        let Some(key) = object.get(key_start..i).and_then(|k| std::str::from_utf8(k).ok()) else { break };
        i += 1;
        while object.get(i).is_some_and(|b| b.is_ascii_whitespace() || *b == b':') {
            i += 1;
        }
        let value_start = i;
        let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
        while let Some(&b) = object.get(i) {
            if in_string {
                match (escaped, b) {
                    (true, _) => escaped = false,
                    (false, b'\\') => escaped = true,
                    (false, b'"') => in_string = false,
                    _ => {}
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' if depth > 0 => depth -= 1,
                    b',' | b'}' if depth == 0 => break,
                    _ => {}
                }
            }
            i += 1;
        }
        if let Some(value) = object.get(value_start..i) {
            out.push((key, value));
        }
    }
    out
}

fn parse_log(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    let first = data.iter().copied().find(|b| !b.is_ascii_whitespace());
    if first == Some(b'{') {
        let mut count = 0usize;
        let mut n = 0u64;
        for object in json_objects(&data) {
            for (event, body) in members(object) {
                n += 1;
                let parsed = (body.len() <= MAX_JSON).then(|| serde_json::from_slice::<Value>(body).ok()).flatten();
                match parsed.and_then(|v| json_entry(event, &v)) {
                    Some(e) => {
                        count += 1;
                        sink.emit(Loc::Offset(n - 1), &e)?;
                    }
                    None => {
                        sink.warn(format!("JSON event {n} (\"{}\") is not a sudo event; skipped", event.escape_debug()))
                    }
                }
            }
        }
        return if count == 0 { Err(Error::skipped("no sudo JSON events")) } else { Ok(()) };
    }
    // Classic: an indented line continues the entry before it.
    let mut pending: Option<(u64, String)> = None;
    let mut seen = false;
    let mut flush = |sink: &mut Sink, pending: &mut Option<(u64, String)>| -> Result<()> {
        if let Some((number, line)) = pending.take() {
            match classic_entry(input, &line) {
                Some(entry) => {
                    seen = true;
                    sink.emit(Loc::Line(number), &entry)?;
                }
                None => sink.warn(format!("line {number}: not a sudo log entry; skipped")),
            }
        }
        Ok(())
    };
    let mut result = Ok(());
    let reader = Input { data: &data, ..*input };
    for_each_line(&reader, |line| {
        let text = lossy(line.bytes);
        if text.starts_with([' ', '\t']) && pending.is_some() {
            if let Some((_, current)) = pending.as_mut() {
                if current.len() < 64 << 10 {
                    current.push(' ');
                    current.push_str(text.trim());
                }
            }
        } else if !text.trim().is_empty() {
            flush(sink, &mut pending)?;
            pending = Some((line.number, text.trim_end().to_string()));
        }
        Ok(())
    })
    .and_then(|()| flush(sink, &mut pending))
    .unwrap_or_else(|e| result = Err(e));
    result?;
    if seen {
        Ok(())
    } else {
        Err(Error::format("no sudo log entries"))
    }
}

// ---- sudo-timestamps and sudo-lectured ----

#[derive(Serialize)]
struct Cache<'a> {
    user: &'a str,
    uid: Option<u32>,
    /// The file's modification time: when this user last authenticated with sudo.
    last_authenticated: Option<Timestamp>,
    /// How many timestamp records the file holds (one lock record plus one per terminal or
    /// parent process authenticated); None when the file is not in the version 2 layout.
    entries: Option<u32>,
}

impl Record for Cache<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} last authenticated with sudo", self.user);
        self.last_authenticated.map(|ts| Event::new(ts, "sudo_authenticated", message)).into_iter()
    }
}

fn mtime(input: &Input) -> Option<Timestamp> {
    (input.mtime > 0).then(|| Timestamp::checked(input.mtime, 0, Precision::Seconds, Basis::Recorded)).flatten()
}

/// Walks `struct timestamp_entry` records (version 2: a 16-bit version and size lead each one).
fn count_entries(data: &[u8]) -> Option<u32> {
    let (mut at, mut count) = (0usize, 0u32);
    while at < data.len() && count < 1_000_000 {
        let head = data.get(at..at + 4)?;
        let (version, size) =
            (u16::from_le_bytes([head[0], head[1]]), usize::from(u16::from_le_bytes([head[2], head[3]])));
        if version != 2 || size < 4 {
            return None;
        }
        at = at.checked_add(size)?;
        count += 1;
    }
    (at == data.len()).then_some(count)
}

/// The user a cache file is for. sudo before 1.9.17 names the file after the user; 1.9.17 and
/// later after the UID, which `etc/passwd` then turns into a name.
fn who(input: &Input) -> (String, Option<u32>) {
    let name = input.path.rsplit('/').next().unwrap_or("");
    match name.parse::<u32>() {
        Ok(uid) => (passwd_lookup::by_uid(input.host).get(&uid).cloned().unwrap_or_default(), Some(uid)),
        Err(_) => (name.to_string(), passwd_lookup::by_name(input.host).get(name).copied()),
    }
}

fn parse_timestamps(input: &Input, sink: &mut Sink) -> Result<()> {
    let (user, uid) = who(input);
    sink.emit(
        Loc::None,
        &Cache { user: &user, uid, last_authenticated: mtime(input), entries: count_entries(input.data) },
    )
}

#[derive(Serialize)]
struct Lectured<'a> {
    user: &'a str,
    uid: Option<u32>,
    /// The file's modification time: when the user was shown the lecture (the first sudo use).
    lectured: Option<Timestamp>,
}

impl Record for Lectured<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} was shown the sudo lecture (first sudo use)", self.user);
        self.lectured.map(|ts| Event::new(ts, "sudo_lectured", message)).into_iter()
    }
}

fn parse_lectured(input: &Input, sink: &mut Sink) -> Result<()> {
    let (user, uid) = who(input);
    sink.emit(Loc::None, &Lectured { user: &user, uid, lectured: mtime(input) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use nixcavate_core::time::{month_from_abbrev, secs_from_civil};
    use std::path::{Path, PathBuf};

    const HOSTS: [&str; 3] = ["debian12", "rocky9", "centos7"];

    fn records(out: &str) -> Vec<Value> {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn text(name: &str) -> String {
        String::from_utf8(fixture(name)).unwrap()
    }

    fn root(host: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/sudo").join(host)
    }

    /// The session directories (`00/00/01`) under a host's `sudo-io`, in order.
    fn sessions(host: &str) -> Vec<String> {
        let mut found = Vec::new();
        for a in std::fs::read_dir(root(host).join("sudo-io")).unwrap().flatten().filter(|e| e.path().is_dir()) {
            for b in std::fs::read_dir(a.path()).unwrap().flatten() {
                for c in std::fs::read_dir(b.path()).unwrap().flatten() {
                    found.push(format!(
                        "{}/{}/{}",
                        a.file_name().to_string_lossy(),
                        b.file_name().to_string_lossy(),
                        c.file_name().to_string_lossy()
                    ));
                }
            }
        }
        found.sort();
        found
    }

    /// Parses one session as a host would hold it: its log files and timing in place.
    fn session_output(host: &str, session: &str, log: &str) -> String {
        let dir = format!("var/log/sudo-io/{session}");
        let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
        for name in ["log", "log.json", "timing"] {
            if let Ok(data) = std::fs::read(root(host).join("sudo-io").join(session).join(name)) {
                owned.push((format!("{dir}/{name}"), data));
            }
        }
        let files: Vec<(&str, &[u8])> = owned.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        run_on_host(&IOLOG, &files, &format!("{dir}/{log}"), 0)
    }

    /// `Nov 13 02:37:24 2026`, the form sudoreplay prints (the containers ran in UTC).
    fn replay_time(text: &str) -> String {
        let t: Vec<&str> = text.split_whitespace().collect();
        let hms: Vec<u32> = t[2].split(':').map(|v| v.parse().unwrap()).collect();
        let month = month_from_abbrev(t[0].as_bytes()).unwrap();
        let secs =
            secs_from_civil(t[3].parse().unwrap(), month, t[1].parse().unwrap(), hms[0], hms[1], hms[2]).unwrap();
        Timestamp::from_secs(secs, Basis::Recorded).to_rfc3339()
    }

    /// Every session of three real sudo versions, record by record against `sudoreplay -l`, and
    /// the byte counts against the real size of each stream.
    #[test]
    fn io_sessions_match_sudoreplay_and_the_stream_files() {
        let mut compared = 0;
        for host in HOSTS {
            let list = text(&format!("sudo/{host}/sudoreplay-list.txt"));
            let streams = text(&format!("sudo/{host}/stream-bytes.txt"));
            let dirs = sessions(host);
            assert_eq!(list.lines().count(), dirs.len(), "{host}");
            for (line, session) in list.lines().zip(&dirs) {
                // `Nov 13 02:37:24 2026 : alice : TTY=pts/1 ; CWD=/tmp ; USER=bob ; TSID=000005 ; COMMAND=...`
                let (stamp, rest) = line.split_once(" : ").unwrap();
                let (user, rest) = rest.split_once(" : ").unwrap();
                let (fields, command) = rest.split_once(" ; COMMAND=").unwrap();
                let value = |key: &str| fields.split(" ; ").find_map(|f| f.strip_prefix(key)).unwrap_or("").to_string();
                let log =
                    if root(host).join("sudo-io").join(session).join("log.json").exists() { "log.json" } else { "log" };
                let out = session_output(host, session, log);
                let rec = &records(&out)[0];
                let at = format!("{host} {session}: {line}\n{out}");
                assert_eq!(&rec["time"].as_str().unwrap()[..19], &replay_time(stamp)[..19], "{at}");
                assert_eq!(rec["user"], user, "{at}");
                assert_eq!(rec["run_user"], value("USER="), "{at}");
                assert_eq!(rec["cwd"], value("CWD="), "{at}");
                assert_eq!(session.replace('/', ""), value("TSID="), "{at}");
                // sudoreplay quotes arguments with spaces; the record has them as sudo logged them.
                assert_eq!(rec["command"].as_str().unwrap().replace('\'', ""), command.replace('\'', ""), "{at}");
                let tty = value("TTY=");
                // sudoreplay prints the terminal without `/dev/`, and `unknown` or `console` when
                // there is none or it is not a pty; the legacy log holds `unknown`.
                let logged = rec["tty"].as_str().unwrap();
                assert!(
                    logged.ends_with(&tty) || ["unknown", "console", ""].contains(&tty.as_str()) || logged.is_empty(),
                    "{tty} {at}"
                );
                for (field, stream) in [
                    ("stdin_bytes", "stdin"),
                    ("stdout_bytes", "stdout"),
                    ("stderr_bytes", "stderr"),
                    ("tty_in_bytes", "ttyin"),
                    ("tty_out_bytes", "ttyout"),
                ] {
                    let key = format!("./{session}/{stream} ");
                    let real: u64 = streams.lines().find_map(|l| l.strip_prefix(&key)).unwrap().trim().parse().unwrap();
                    assert_eq!(rec[field].as_u64().unwrap(), real, "{field}: {at}");
                }
                compared += 1;
            }
        }
        assert!(compared >= 20, "{compared}");
    }

    #[test]
    fn a_session_with_both_log_forms_is_reported_once_and_streams_are_not_read() {
        let out = session_output("debian12", "00/00/02", "log");
        assert!(out.contains("skipped: log.json in the same session is read instead"), "{out}");
        let out = session_output("debian12", "00/00/02", "log.json");
        let rec = &records(&out)[0];
        assert!(
            rec["duration_seconds"].as_f64().unwrap() >= 1.0 && rec["duration_seconds"].as_f64().unwrap() < 3.0,
            "{out}"
        );
        assert!(out.contains("alice ran /bin/sh -c echo out-one"), "{out}");
        insta::assert_snapshot!(out);
        // The legacy log alone (sudo 1.8) works the same way.
        let out = session_output("centos7", "00/00/02", "log");
        assert!(out.contains(r#""log_format":"legacy""#) && out.contains(r#""stdout_bytes":16"#), "{out}");
    }

    #[test]
    fn io_log_edge_cases() {
        let run_log = |log: &[u8], timing: Option<&[u8]>| {
            let mut files: Vec<(&str, &[u8])> = vec![("var/log/sudo-io/00/00/01/log", log)];
            if let Some(t) = timing {
                files.push(("var/log/sudo-io/00/00/01/timing", t));
            }
            run_on_host(&IOLOG, &files, "var/log/sudo-io/00/00/01/log", 0)
        };
        let legacy = b"1700000000:alice:root:wheel:/dev/pts/4:24:80\n/home/alice\n/usr/bin/vi /etc/hosts\n";
        let out = run_log(legacy, Some(b"4 0.5 10\n3 1.25 3\n6 0.1 24 80\n5 2 SIGTSTP\n7 0 0\n"));
        assert!(out.contains(r#""tty":"/dev/pts/4","cwd":"/home/alice","command":"/usr/bin/vi /etc/hosts""#), "{out}");
        assert!(out.contains(r#""duration_seconds":3.85,"stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,"tty_in_bytes":3,"tty_out_bytes":10"#), "{out}");
        assert!(run_log(legacy, None).contains("timing is missing or unreadable"));
        let out = run_log(legacy, Some(b"4 abc 10\n9 1 1\nx\n"));
        assert!(out.contains("timing lines not understood"), "{out}");
        assert!(run_log(b"not a log\n", None).contains("not a sudo I/O session log"));
        assert!(run_log(b"", None).contains("not a sudo I/O session log"));
    }

    fn log_on(host: &str, file: &str, path: &str, mtime: i64) -> String {
        let data = fixture(&format!("sudo/{host}/{file}"));
        run_on_host(&LOG, &[(path, &data)], path, mtime)
    }

    #[test]
    fn classic_log_matches_sudoreplay_and_wraps_correctly() {
        for host in HOSTS {
            let list = text(&format!("sudo/{host}/sudoreplay-list.txt"));
            let out = log_on(host, "sudo.log", "var/log/sudo.log", 1_794_540_000);
            let recs = records(&out);
            let raw = text(&format!("sudo/{host}/sudo.log"));
            // One record per entry, however many lines sudo wrapped it over.
            let entries = raw.lines().filter(|l| !l.starts_with(char::is_whitespace)).count();
            assert_eq!(recs.len(), entries, "{host}");
            let accepted: Vec<&Value> = recs.iter().filter(|r| r["message"] == "").collect();
            let first_in_list: Vec<&str> = list.lines().take(accepted.len()).collect();
            assert_eq!(accepted.len(), first_in_list.len(), "{host}");
            for (rec, line) in accepted.iter().zip(&first_in_list) {
                // sudoreplay's TSID has six digits; 1.9 logs two... compare the numeric value.
                let tsid = line.split(" ; ").find_map(|f| f.strip_prefix("TSID=")).unwrap().trim_start_matches('0');
                assert_eq!(rec["tsid"].as_str().unwrap().trim_start_matches('0'), tsid, "{host} {line}");
                let command = line.split(" ; COMMAND=").nth(1).unwrap().replace('\'', "");
                assert_eq!(rec["command"].as_str().unwrap().replace('\'', ""), command, "{host}");
                assert!(rec["time"].as_str().unwrap().starts_with("2026-11-13T"), "{host}");
            }
            let wrong = recs.iter().find(|r| r["message"].as_str().unwrap().contains("incorrect password")).unwrap();
            assert_eq!(wrong["message"], "1 incorrect password attempt", "{host}");
            assert_eq!(wrong["command"], "/bin/true");
            assert_eq!(wrong["time_basis"], "inferred_year_assumed_zone");
        }
        insta::assert_snapshot!(log_on("rocky9", "sudo.log", "var/log/sudo.log", 1_794_540_000));
    }

    #[test]
    fn json_log_matches_sudoreplay() {
        for host in ["debian12", "rocky9"] {
            let out = log_on(host, "sudo.json", "var/log/sudo.json", 0);
            let recs = records(&out);
            // The file is one object whose `accept` key repeats; every event must survive.
            let events: Vec<&str> = recs.iter().map(|r| r["event"].as_str().unwrap()).collect();
            assert_eq!(events, ["accept", "accept", "reject"], "{host}: {out}");
            let list = text(&format!("sudo/{host}/sudoreplay-list.txt"));
            for rec in recs.iter().filter(|r| r["event"] == "accept") {
                let command = rec["command"].as_str().unwrap().replace('\'', "");
                let listed = list.lines().find(|l| l.replace('\'', "").ends_with(&format!("COMMAND={command}")));
                let listed = listed.unwrap_or_else(|| panic!("{host}: {command} is not in sudoreplay's list"));
                // The JSON event time is the server's, within a second of the session's.
                let stamp = listed.split(" : ").next().unwrap();
                let wanted = replay_time(stamp);
                let got = rec["time"].as_str().unwrap();
                assert!(got[..16] == wanted[..16], "{got} vs {wanted}");
                assert_eq!(rec["time_basis"], "recorded");
            }
            assert!(recs
                .iter()
                .any(|r| r["event"] == "reject" && r["message"].as_str().unwrap().contains("incorrect password")));
        }
        insta::assert_snapshot!(log_on("debian12", "sudo.json", "var/log/sudo.json", 0));
    }

    #[test]
    fn log_edge_cases() {
        let out = run(
            &LOG,
            "var/log/sudo.log",
            b"Nov 13 02:32:54 2026 : alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo a ; b\n",
            0,
        );
        assert!(
            out.contains(r#""time":"2026-11-13T02:32:54Z""#) && out.contains(r#""command":"/bin/echo a ; b""#),
            "{out}"
        );
        assert!(out.contains(r#""time_basis":"assumed_zone""#), "{out}");
        let denied = run(
            &LOG,
            "var/log/sudo.log",
            b"Nov 13 02:32:54 : bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id\n",
            1_794_540_000,
        );
        assert!(denied.contains("sudo_denied") && denied.contains("user NOT in sudoers"), "{denied}");
        assert!(run(&LOG, "var/log/sudo.log", b"garbage\n", 0).contains("no sudo log entries"));
        assert!(run(&LOG, "var/log/sudo.json", b"{\"accept\": {\"submituser\": \"a\"} {broken", 1).contains("skipped"));
        assert!(run(&LOG, "var/log/sudo.json", br#"{"x": 1}"#, 1).contains("not a sudo event"));
    }

    #[test]
    fn timestamp_and_lectured_files() {
        let passwd = fixture("sudo/centos7/passwd");
        let size: usize = text("sudo/centos7/state-files.txt")
            .lines()
            .find(|l| l.starts_with("/run/sudo/ts/alice"))
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let ts = fixture("sudo/centos7/state-run/ts/alice");
        assert_eq!(ts.len(), size);
        let files: [(&str, &[u8]); 2] = [("run/sudo/ts/alice", &ts), ("etc/passwd", &passwd)];
        let out = run_on_host(&TIMESTAMPS, &files, "run/sudo/ts/alice", 1_794_537_489);
        // The file is a whole number of 56-byte timestamp_entry records.
        assert!(out.contains(&format!(r#""entries":{}"#, size / 56)), "{out}");
        assert!(out.contains(r#""user":"alice","uid":1000,"last_authenticated":"2026-11-13T02:38:09Z""#), "{out}");
        assert!(out.contains("alice last authenticated with sudo"), "{out}");
        // 1.9.17 names the file after the UID.
        let passwd = fixture("sudo/rocky9/passwd");
        let files: [(&str, &[u8]); 2] =
            [("run/sudo/ts/1000", &fixture("sudo/rocky9/state-run/ts/1000")), ("etc/passwd", &passwd)];
        assert!(run_on_host(&TIMESTAMPS, &files, "run/sudo/ts/1000", 1_794_537_473)
            .contains(r#""user":"alice","uid":1000"#));
        let out = run_on_host(
            &LECTURED,
            &[("var/db/sudo/lectured/alice", b""), ("etc/passwd", &fixture("sudo/centos7/passwd"))],
            "var/db/sudo/lectured/alice",
            1_794_537_485,
        );
        assert!(out.contains("alice was shown the sudo lecture") && out.contains("2026-11-13T02:38:05Z"), "{out}");
        // A file that is not in the 1.8.10+ layout still gets its user and time.
        assert!(run(&TIMESTAMPS, "run/sudo/ts/x", b"garbage", 1_700_000_000).contains(r#""entries":null"#));
    }

    #[test]
    fn mutations_never_panic() {
        let mut seed = 0xfeed_beef_1234_5678u64;
        let json = fixture("sudo/debian12/sudo.json");
        let classic = fixture("sudo/centos7/sudo.log");
        let legacy = std::fs::read(root("centos7").join("sudo-io/00/00/02/log")).unwrap();
        for round in 0..1500 {
            for (artifact, path, data) in [
                (&LOG, "var/log/sudo.json", &json),
                (&LOG, "var/log/sudo.log", &classic),
                (&IOLOG, "var/log/sudo-io/00/00/01/log", &legacy),
            ] {
                let mut copy = data.clone();
                for _ in 0..(1 + round % 6) {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    let at = (seed % copy.len() as u64) as usize;
                    copy[at] = (seed >> 32) as u8;
                }
                if round % 5 == 0 {
                    copy.truncate((seed % copy.len() as u64) as usize);
                }
                run(artifact, path, &copy, 1_794_540_000);
            }
        }
    }
}

//! Imports Sigma detections as a timeline run. nixcavate does not run Sigma rules; it merges
//! the results of the tools that do.
//!
//! Two layouts are recognized, both a JSON array (checked against each project's source on
//! 2026-11-11):
//!
//! - **ChopChopGo** `-out json`: one object per detection with `Timestamp`, `Message`,
//!   `Title`, `ID`, `Tags`, `Author` (auditd adds `User`, `Exe`, `Terminal`, `PID`). It has
//!   no rule level. Syslog timestamps are copied from the log line, so they may lack a year.
//! - **Zircolite** `detected_events.json`: one object per rule with `title`, `rule_level`
//!   and `matches`, the matched events. The event time is in `SystemTime`, `UtcTime`,
//!   `@timestamp`, `timestamp` or `_time`.

use nixcavate_artifacts::common::year::utc_without_year;
use nixcavate_core::run::{EventBuffer, Loc, RunHeader, TimelineEvent};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Precision, Timestamp};
use nixcavate_source::Tz;
use serde_json::Value;
use std::fs;
use std::path::Path;

const ZIRCOLITE_TIME_KEYS: [&str; 5] = ["SystemTime", "UtcTime", "@timestamp", "timestamp", "_time"];
const MAX_MESSAGE: usize = 600;

pub struct Imported {
    /// One sorted timeline run.
    pub run: Vec<u8>,
    pub events: u64,
    /// Detections left out because their time could not be read.
    pub skipped: u64,
}

/// Reads a results file. `host` labels the rows; the results themselves do not name one.
pub fn import(path: &Path, host: &str) -> Result<Imported, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    // A syslog time without a year is resolved against the results file's own time: the
    // detections were written after the log lines they quote.
    let reference =
        fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    import_bytes(&bytes, &path.display().to_string(), host, reference.map_or(0, |d| d.as_secs() as i64))
}

fn import_bytes(bytes: &[u8], source: &str, host: &str, reference: i64) -> Result<Imported, String> {
    let document: Value = serde_json::from_slice(bytes).map_err(|e| format!("not valid JSON: {e}"))?;
    let rows = document.as_array().ok_or("expected a JSON array of detections")?;
    let zircolite = rows.iter().any(|row| row.get("matches").is_some());
    let chopchopgo = rows.iter().any(|row| row.get("Timestamp").is_some());
    if !rows.is_empty() && !zircolite && !chopchopgo {
        return Err("neither ChopChopGo nor Zircolite JSON (no `Timestamp` or `matches` keys)".into());
    }

    let mut buffer = EventBuffer::default();
    let mut skipped = 0u64;
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut push = |time: Option<Timestamp>, message: &str, rule: &str, level: &str| match time {
        Some(ts) => {
            let message = cut(message);
            buffer.push(&TimelineEvent { ts, loc: Loc::None, kind: "detection", message, rule, level });
        }
        None => skipped += 1,
    };
    for row in rows {
        if let Some(matches) = row.get("matches").and_then(Value::as_array) {
            let (rule, level) = (text(row, "title"), text(row, "rule_level"));
            for event in matches {
                let time = ZIRCOLITE_TIME_KEYS.iter().find_map(|key| {
                    let raw = event.get(*key)?.as_str()?;
                    // Sysmon's UtcTime is UTC by definition; other zone-less times are assumed UTC.
                    parse_time(raw, reference, *key == "UtcTime")
                });
                push(time, &event.to_string(), &rule, &level);
            }
        } else {
            let time = row.get("Timestamp").and_then(Value::as_str).and_then(|raw| parse_time(raw, reference, false));
            let mut message = text(row, "Message");
            for key in ["User", "Exe", "Terminal", "PID"] {
                if let Some(value) = row.get(key).and_then(Value::as_str).filter(|v| !v.is_empty()) {
                    message.push_str(&format!(
                        "{}{}={value}",
                        if message.is_empty() { "" } else { " " },
                        key.to_lowercase()
                    ));
                }
            }
            push(time, &message, &text(row, "Title"), "");
        }
    }

    let events = buffer.len() as u64;
    let artifact = if zircolite { "sigma-zircolite" } else { "sigma-chopchopgo" };
    let mut run = Vec::new();
    buffer.write_run(&RunHeader { host, artifact, source_path: source }, &mut run).map_err(|e| e.to_string())?;
    Ok(Imported { run, events, skipped })
}

/// Reads an ISO 8601 time, or a syslog `Mon DD HH:MM:SS` time whose year is inferred.
fn parse_time(raw: &str, reference: i64, utc_by_definition: bool) -> Option<Timestamp> {
    let raw = raw.trim().as_bytes();
    if let Some((parsed, _)) = parse_iso8601(raw) {
        let basis = if parsed.offset.is_some() || utc_by_definition { Basis::Recorded } else { Basis::AssumedZone };
        return Some(Timestamp::from_secs_nanos(parsed.secs, parsed.nanos, parsed.precision, basis));
    }
    // `Mar  9 01:02:03`
    let month = month_from_abbrev(raw)?;
    let mut fields = raw.get(3..)?.split(|b| *b == b' ' || *b == b':').filter(|f| !f.is_empty());
    let mut next = || fields.next().and_then(parse_uint).map(|n| n as u32);
    let (day, hour, min, sec) = (next()?, next()?, next()?, next()?);
    let secs = utc_without_year(month, day, hour, min, sec, reference, &Tz::utc())?;
    Some(Timestamp::new(secs.saturating_mul(1_000_000_000), Precision::Seconds, Basis::InferredYearAssumedZone))
}

fn cut(text: &str) -> &str {
    if text.len() <= MAX_MESSAGE {
        return text;
    }
    let mut end = MAX_MESSAGE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use nixcavate_core::run::merge;
    use nixcavate_core::Format;

    fn timeline(json: &str, reference: i64) -> (String, u64) {
        let imported = import_bytes(json.as_bytes(), "results.json", "web01", reference).unwrap();
        let mut out = Vec::new();
        merge(&[&imported.run], Format::Csv, 1, &mut out).unwrap();
        (String::from_utf8(out).unwrap(), imported.skipped)
    }

    #[test]
    fn chopchopgo_rows_keep_their_rule() {
        let json = r#"[
          {"Timestamp": "2023-01-01T00:00:10Z", "Message": "Accepted password for root", "Tags": ["attack.t1078"],
           "Author": "a", "ID": "abc-123", "Title": "Root Login"},
          {"Timestamp": "2023-01-01T00:00:00Z", "User": "alice", "Exe": "/usr/bin/nc", "Terminal": "pts/0", "PID": "42",
           "Tags": [], "Author": "a", "ID": "def-456", "Title": "Netcat Execution"},
          {"Timestamp": "Mar  9 01:02:03", "Message": "from syslog", "Tags": [], "Author": "a", "ID": "x", "Title": "Old Style"},
          {"Timestamp": "garbage", "Message": "dropped", "Tags": [], "Author": "a", "ID": "x", "Title": "Bad Time"}
        ]"#;
        let (csv, skipped) = timeline(json, 1_710_028_800); // 2024-03-10
        assert_eq!(skipped, 1);
        let rows: Vec<&str> = csv.lines().skip(1).collect();
        assert_eq!(
            rows,
            [
                "2023-01-01T00:00:00Z,seconds,recorded,web01,sigma-chopchopgo,detection,user=alice exe=/usr/bin/nc terminal=pts/0 pid=42,results.json,,,Netcat Execution,",
                "2023-01-01T00:00:10Z,seconds,recorded,web01,sigma-chopchopgo,detection,Accepted password for root,results.json,,,Root Login,",
                "2024-03-09T01:02:03Z,seconds,inferred_year_assumed_zone,web01,sigma-chopchopgo,detection,from syslog,results.json,,,Old Style,",
            ]
        );
    }

    #[test]
    fn zircolite_matches_become_rows_with_level() {
        let json = r#"[
          {"title": "Suspicious Curl", "id": "1", "description": "d", "sigmafile": "r.yml", "sigma": "SELECT 1",
           "rule_level": "high", "tags": ["attack.execution"], "count": 2,
           "matches": [
             {"SystemTime": "2025-12-10T04:33:20.562782Z", "Computer": "host1", "CommandLine": "curl x"},
             {"timestamp": "2025-12-10 04:00:00", "exe": "/usr/bin/curl"}
           ]},
          {"title": "No Time", "rule_level": "low", "matches": [{"exe": "/bin/true"}]}
        ]"#;
        let (csv, skipped) = timeline(json, 0);
        assert_eq!(skipped, 1);
        let rows: Vec<&str> = csv.lines().skip(1).collect();
        assert_eq!(rows.len(), 2);
        assert!(
            rows[0].starts_with("2025-12-10T04:00:00Z,seconds,assumed_zone,web01,sigma-zircolite,detection,"),
            "{}",
            rows[0]
        );
        assert!(rows[0].ends_with(",results.json,,,Suspicious Curl,high"), "{}", rows[0]);
        assert!(rows[1].starts_with("2025-12-10T04:33:20.562782Z,micros,recorded,web01,sigma-zircolite,detection,"));
        assert!(rows[1].contains("curl x"));
    }

    #[test]
    fn rejects_other_json() {
        assert!(import_bytes(b"{}", "x", "h", 0).is_err());
        assert!(import_bytes(b"[{\"a\": 1}]", "x", "h", 0).is_err());
        assert!(import_bytes(b"not json", "x", "h", 0).is_err());
        assert_eq!(import_bytes(b"[]", "x", "h", 0).unwrap().events, 0);
    }
}

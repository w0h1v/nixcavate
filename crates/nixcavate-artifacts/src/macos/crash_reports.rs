//! Crash and diagnostic reports in `DiagnosticReports` (and `Retired`): `.ips` (macOS 12+: a
//! one-line JSON header, then a JSON body), legacy `.crash`, `.hang`, `.spin`, `.diag`,
//! `.shutdownStall` and `.panic` text reports.
//!
//! Format references: Apple's "Understanding the exception types in a crash report" and
//! "Examining the fields in a crash report" (developer.apple.com), and the field names of
//! published `.ips` samples in public write-ups. Only header and summary fields are kept; the
//! thread dump is never copied (at most the top frames of the faulting thread, as names).
//!
//! Synthetic only: no real report was read. The doubts are the `.ips` key names on macOS
//! versions other than 12-14 and the layout of the `.panic` text of old Intel Macs.

use super::util::clip;
use crate::common::home::user_from_path;
use crate::text::lossy;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::{Map, Value};

pub const ARTIFACT: Artifact = Artifact::new(
    "crash-reports",
    "macOS crash, hang and panic reports",
    Category::Execution,
    MACOS,
    &[
        "Library/Logs/DiagnosticReports/*",
        "Library/Logs/DiagnosticReports/Retired/*",
        "Users/*/Library/Logs/DiagnosticReports/*",
        "Users/*/Library/Logs/DiagnosticReports/Retired/*",
        "private/var/root/Library/Logs/DiagnosticReports/*",
    ],
    parse,
);

/// A JSON body larger than this is not parsed; the header still gives the main fields.
const MAX_BODY: usize = 32 << 20;
/// Lines and bytes of a text report searched for header fields.
const HEADER_LINES: usize = 150;
const TOP_FRAMES: usize = 8;

#[derive(Serialize, Default)]
struct Report<'a> {
    user: &'a str,
    /// `ips` or `text`.
    format: &'static str,
    /// `crash`, `hang`, `spin`, `diag`, `cpu_resource`, `shutdown_stall`, `panic` or `other`.
    report_kind: &'static str,
    retired: bool,
    time: Option<Timestamp>,
    process: Option<String>,
    pid: Option<i64>,
    executable_path: Option<String>,
    bundle_id: Option<String>,
    app_version: Option<String>,
    os_version: Option<String>,
    incident_id: Option<String>,
    bug_type: Option<String>,
    exception_type: Option<String>,
    exception_signal: Option<String>,
    exception_subtype: Option<String>,
    termination: Option<String>,
    crashed_thread: Option<i64>,
    /// `image symbol` of the first frames of the faulting thread.
    crashed_thread_frames: Vec<String>,
    parent_process: Option<String>,
    parent_pid: Option<i64>,
    responsible_process: Option<String>,
    code_signing_id: Option<String>,
    team_id: Option<String>,
    /// True when the process ran translated by Rosetta 2.
    translated: Option<bool>,
    panic_string: Option<String>,
    kernel_version: Option<String>,
}

impl Record for Report<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = self.process.as_deref().or(self.bundle_id.as_deref()).unwrap_or("a process");
        let message = match (self.report_kind, self.exception_type.as_deref()) {
            ("panic", _) => "kernel panic".to_string(),
            (_, Some(kind)) => format!("{who} crashed ({kind})"),
            (kind, None) => format!("{who} produced a {kind} report"),
        };
        self.time.map(|ts| Event::new(ts, "crashed", message)).into_iter()
    }
}

fn report_kind(path: &str, bug_type: Option<&str>) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or_default();
    if name.contains(".cpu_resource.") {
        return "cpu_resource";
    }
    match name.rsplit_once('.').map(|(_, ext)| ext) {
        Some("crash") => "crash",
        Some("hang") => "hang",
        Some("spin") => "spin",
        Some("diag") => "diag",
        Some("panic") => "panic",
        Some("shutdownStall") => "shutdown_stall",
        Some("ips") => match bug_type {
            Some("210") => "panic",
            Some("309") => "crash",
            Some("385" | "288") => "diag",
            _ => "crash",
        },
        _ => "other",
    }
}

fn text_of(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) if !s.is_empty() => Some(clip(s, 512)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn int_of(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}

/// `2023-11-14 10:00:00.00 -0800`: the zone follows a space, which the ISO form does not have.
fn time_of(text: &str) -> Option<Timestamp> {
    let text = text.trim();
    let (clock, zone) = (text.get(..19)?, text.get(19..)?);
    let (fraction, zone) = zone.split_once(' ').unwrap_or((zone, ""));
    parse_iso8601(format!("{clock}{fraction}{zone}").as_bytes())?.0.recorded()
}

/// `.ips`: header line, then the body object. An old single-object file has only a body.
fn parse_ips(input: &Input, sink: &mut Sink, retired: bool) -> Result<()> {
    let split = memchr::memchr(b'\n', input.data).unwrap_or(input.data.len());
    let head: Value =
        serde_json::from_slice(&input.data[..split]).map_err(|e| Error::format(format!("ips header: {e}")))?;
    if !head.is_object() {
        return Err(Error::format("ips header is not a JSON object"));
    }
    let rest = input.data.get(split + 1..).unwrap_or_default();
    let body: Value = if rest.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else if rest.len() > MAX_BODY {
        sink.warn(format!("report body of {} MiB not parsed; header fields only", rest.len() >> 20));
        Value::Null
    } else {
        serde_json::from_slice(rest).unwrap_or_else(|e| {
            sink.warn(format!("report body is not valid JSON ({e}); header fields only"));
            Value::Null
        })
    };
    let empty = Value::Object(Map::new());
    let body = if body.is_object() { &body } else { &empty };
    let bug_type = text_of(&head, "bug_type");
    let exception = body.get("exception").unwrap_or(&empty);
    let termination = body.get("termination").unwrap_or(&empty);
    let bundle = body.get("bundleInfo").unwrap_or(&empty);
    let time = text_of(body, "captureTime").or_else(|| text_of(&head, "timestamp")).and_then(|t| time_of(&t));
    let faulting = int_of(body, "faultingThread");
    let report = Report {
        user: user_from_path(input.path),
        format: "ips",
        report_kind: report_kind(input.path, bug_type.as_deref()),
        retired,
        time,
        process: text_of(body, "procName").or_else(|| text_of(&head, "app_name")).or_else(|| text_of(&head, "name")),
        pid: int_of(body, "pid"),
        executable_path: text_of(body, "procPath"),
        bundle_id: text_of(bundle, "CFBundleIdentifier").or_else(|| text_of(&head, "bundleID")),
        app_version: text_of(bundle, "CFBundleShortVersionString").or_else(|| text_of(&head, "app_version")),
        os_version: text_of(&head, "os_version").or_else(|| body.get("osVersion").and_then(|o| text_of(o, "train"))),
        incident_id: text_of(&head, "incident_id").or_else(|| text_of(body, "incident")),
        bug_type,
        exception_type: text_of(exception, "type"),
        exception_signal: text_of(exception, "signal"),
        exception_subtype: text_of(exception, "subtype"),
        termination: text_of(termination, "indicator").or_else(|| text_of(termination, "namespace")),
        crashed_thread: faulting,
        crashed_thread_frames: faulting.map(|t| top_frames(body, t)).unwrap_or_default(),
        parent_process: text_of(body, "parentProc"),
        parent_pid: int_of(body, "parentPid"),
        responsible_process: text_of(body, "responsibleProc"),
        code_signing_id: text_of(body, "codeSigningID"),
        team_id: text_of(body, "codeSigningTeamID"),
        translated: body.get("translated").and_then(Value::as_bool),
        panic_string: text_of(body, "panicString"),
        kernel_version: text_of(body, "kernel").or_else(|| text_of(body, "kernelVersion")),
    };
    sink.emit(Loc::None, &report)
}

fn top_frames(body: &Value, thread: i64) -> Vec<String> {
    let Some(frames) = usize::try_from(thread)
        .ok()
        .and_then(|i| body.get("threads")?.as_array()?.get(i))
        .and_then(|t| t.get("frames")?.as_array())
    else {
        return Vec::new();
    };
    let images = body.get("usedImages").and_then(Value::as_array);
    frames
        .iter()
        .take(TOP_FRAMES)
        .map(|frame| {
            let image = frame
                .get("imageIndex")
                .and_then(Value::as_u64)
                .and_then(|i| images?.get(usize::try_from(i).ok()?))
                .and_then(|image| image.get("name")?.as_str())
                .unwrap_or("?");
            let symbol = frame.get("symbol").and_then(Value::as_str).unwrap_or("?");
            clip(&format!("{image} {symbol}"), 200)
        })
        .collect()
}

/// `Key:   value` lines of a text report's header; the first line of each key wins.
fn text_fields(text: &str) -> Vec<(&str, &str)> {
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for line in text.lines().take(HEADER_LINES) {
        if line.starts_with("Thread 0") || line.starts_with("Application Specific") {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            if !key.is_empty() && key.len() < 40 && !fields.iter().any(|(k, _)| *k == key) {
                fields.push((key, value.trim()));
            }
        }
    }
    fields
}

/// `Safari [1234]` into the name and the number.
fn name_and_pid(value: &str) -> (String, Option<i64>) {
    match value.rsplit_once(" [") {
        Some((name, rest)) => (clip(name.trim(), 256), rest.trim_end_matches(']').trim().parse().ok()),
        None => (clip(value, 256), None),
    }
}

fn parse_text(input: &Input, sink: &mut Sink, retired: bool) -> Result<()> {
    // Reports are text; a binary file with the right extension is not one.
    let head = &input.data[..input.data.len().min(64 << 10)];
    if head.contains(&0) {
        return Err(Error::format("not a text report"));
    }
    let text = lossy(head);
    let fields = text_fields(&text);
    let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).filter(|v| !v.is_empty());
    let kind = report_kind(input.path, None);
    let (process, pid) = get("Process").or_else(|| get("Command")).map(name_and_pid).unzip();
    let parent = get("Parent Process").map(name_and_pid);
    let responsible = get("Responsible").map(name_and_pid);
    let (exception_type, signal) = match get("Exception Type") {
        Some(t) => match t.split_once(" (") {
            Some((kind, sig)) => (Some(clip(kind, 128)), Some(clip(sig.trim_end_matches(')'), 64))),
            None => (Some(clip(t, 128)), None),
        },
        None => (None, None),
    };
    // Panic reports: `panic(cpu N caller 0x...): "string"`, then `Kernel version:` and the
    // version on the next line.
    let mut lines = text.lines();
    let mut panic_string = None;
    let mut kernel_version = None;
    let mut os_build = None;
    while let Some(line) = lines.next() {
        if panic_string.is_none() && line.starts_with("panic(") {
            panic_string = Some(clip(line, 1024));
        } else if line.starts_with("Kernel version:") {
            kernel_version = lines.next().map(|l| clip(l.trim(), 256));
        } else if line.starts_with("Mac OS version:") {
            os_build = lines.next().map(|l| clip(l.trim(), 64));
        }
    }
    let kind = if panic_string.is_some() && kind == "other" { "panic" } else { kind };
    let report = Report {
        user: user_from_path(input.path),
        format: "text",
        report_kind: kind,
        retired,
        time: get("Date/Time").and_then(time_of),
        process: process.filter(|p| !p.is_empty()),
        pid: pid.flatten(),
        executable_path: get("Path").map(|p| clip(p, 512)),
        bundle_id: get("Identifier").map(|p| clip(p, 256)),
        app_version: get("Version").map(|p| clip(p, 128)),
        os_version: get("OS Version").map(|p| clip(p, 128)).or(os_build),
        incident_id: get("Incident Identifier").map(|p| clip(p, 128)),
        exception_type,
        exception_signal: signal,
        exception_subtype: get("Exception Subtype").map(|p| clip(p, 256)),
        termination: get("Termination Reason").map(|p| clip(p, 256)),
        crashed_thread: get("Crashed Thread").and_then(|t| t.split_whitespace().next()?.parse().ok()),
        parent_process: parent.as_ref().map(|(n, _)| n.clone()),
        parent_pid: parent.and_then(|(_, p)| p),
        responsible_process: responsible.map(|(n, _)| n),
        code_signing_id: None,
        team_id: None,
        translated: get("Code Type").map(|t| t.contains("X86-64") && t.contains("Translated")),
        panic_string,
        kernel_version,
        ..Report::default()
    };
    if report.time.is_none() && report.process.is_none() && report.panic_string.is_none() {
        return Err(Error::skipped("no report header fields found"));
    }
    sink.emit(Loc::None, &report)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    let retired = input.path.contains("/Retired/");
    match ext {
        "ips" => parse_ips(input, sink, retired),
        "crash" | "hang" | "spin" | "diag" | "panic" | "shutdownStall" => parse_text(input, sink, retired),
        _ => Err(Error::skipped("not a crash report file type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const IPS: &str = "Users/alice/Library/Logs/DiagnosticReports/Example_2023-11-14-100000_host.ips";

    #[test]
    fn ips_report() {
        insta::assert_snapshot!(run(&ARTIFACT, IPS, &fixture("crash-reports/Example.ips"), 0));
    }

    #[test]
    fn legacy_crash_hang_and_panic_text() {
        let crash = "Library/Logs/DiagnosticReports/Retired/Old_2019-01-01-000000_host.crash";
        insta::assert_snapshot!(run(&ARTIFACT, crash, &fixture("crash-reports/Old.crash"), 0));
        let panic = "Library/Logs/DiagnosticReports/Kernel_2019-01-01-000000_host.panic";
        insta::assert_snapshot!(run(&ARTIFACT, panic, &fixture("crash-reports/Kernel.panic"), 0));
    }

    #[test]
    fn the_thread_dump_is_not_copied() {
        let out = run(&ARTIFACT, IPS, &fixture("crash-reports/Example.ips"), 0);
        assert!(!out.contains("PLANTED-THREAD-DUMP-STATE"), "{out}");
        assert!(!out.contains("usedImages"), "{out}");
    }

    #[test]
    fn unknown_types_and_garbage() {
        let path = "Library/Logs/DiagnosticReports/x.plist";
        assert!(run(&ARTIFACT, path, b"x", 0).contains("skipped: not a crash report file type"));
        assert!(run(&ARTIFACT, IPS, b"not json", 0).contains("failed: "));
        assert!(run(&ARTIFACT, IPS, b"", 0).contains("failed: "));
        let text = "Library/Logs/DiagnosticReports/x.crash";
        assert!(run(&ARTIFACT, text, b"hello\nworld\n", 0).contains("skipped: no report header"));
    }

    #[test]
    fn damaged_reports_do_not_panic() {
        for name in ["Example.ips", "Old.crash", "Kernel.panic"] {
            let data = fixture(&format!("crash-reports/{name}"));
            let path = format!("Library/Logs/DiagnosticReports/{name}");
            crate::macos::plist_util::tests::survives_damage(&ARTIFACT, &path, &data);
        }
    }

    #[test]
    fn deep_json_is_refused_not_recursed() {
        let mut data = b"{\"app_name\":\"x\"}\n".to_vec();
        data.extend(b"[".repeat(100_000));
        let out = run(&ARTIFACT, IPS, &data, 0);
        assert!(out.contains("not valid JSON"), "{out}");
    }
}

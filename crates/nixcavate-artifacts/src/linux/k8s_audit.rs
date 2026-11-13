//! The Kubernetes API server audit log: one JSON `audit.k8s.io/v1` Event per line, written to
//! the path given by `--audit-log-path` (kubeadm clusters use `var/log/kubernetes/audit/` or
//! `var/log/kube-apiserver/`, k3s `var/lib/rancher/k3s/server/logs/audit.log`). The file exists
//! only when the cluster was started with an audit policy. Field reference: the Kubernetes
//! `Event` type of `k8s.io/apiserver/pkg/apis/audit/v1`.
//!
//! Every event is a record. Only the ones an investigation starts from reach the timeline:
//! `exec`, `attach` and `port-forward` into pods, reads of secrets, creates, deletes and
//! changes of pods, roles and bindings, and anonymous requests, all but the last only when
//! made by a user that is not a cluster component (`system:node:*`, `system:kube-*`, ...).

use crate::text::for_each_line;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "k8s-audit",
    "Kubernetes API server audit log",
    Category::Logs,
    LINUX,
    &[
        "var/log/kubernetes/audit/audit*.log*",
        "var/log/kubernetes/audit*.log*",
        "var/log/kube-apiserver/audit*.log*",
        "var/lib/rancher/k3s/server/logs/audit*.log*",
    ],
    parse,
)
.split_lines();

#[derive(Deserialize, Default)]
struct User<'a> {
    #[serde(borrow, default)]
    username: Cow<'a, str>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize, Default)]
struct ObjectRef<'a> {
    #[serde(borrow, default)]
    resource: Cow<'a, str>,
    #[serde(borrow, default)]
    subresource: Cow<'a, str>,
    #[serde(borrow, default)]
    namespace: Cow<'a, str>,
    #[serde(borrow, default)]
    name: Cow<'a, str>,
    #[serde(rename = "apiGroup", borrow, default)]
    api_group: Cow<'a, str>,
}

#[derive(Deserialize, Default)]
struct Status<'a> {
    #[serde(default)]
    code: Option<i64>,
    #[serde(borrow, default)]
    reason: Cow<'a, str>,
}

#[derive(Deserialize)]
struct Event_<'a> {
    #[serde(rename = "auditID", borrow, default)]
    audit_id: Cow<'a, str>,
    #[serde(borrow, default)]
    level: Cow<'a, str>,
    #[serde(borrow, default)]
    stage: Cow<'a, str>,
    #[serde(rename = "requestURI", borrow, default)]
    request_uri: Cow<'a, str>,
    #[serde(borrow, default)]
    verb: Cow<'a, str>,
    #[serde(borrow, default)]
    user: User<'a>,
    #[serde(rename = "impersonatedUser", borrow, default)]
    impersonated_user: Option<User<'a>>,
    #[serde(rename = "sourceIPs", default)]
    source_ips: Vec<String>,
    #[serde(rename = "userAgent", borrow, default)]
    user_agent: Cow<'a, str>,
    #[serde(rename = "objectRef", borrow, default)]
    object_ref: Option<ObjectRef<'a>>,
    #[serde(rename = "responseStatus", borrow, default)]
    response_status: Option<Status<'a>>,
    #[serde(rename = "requestReceivedTimestamp", borrow, default)]
    received: Cow<'a, str>,
    #[serde(rename = "stageTimestamp", borrow, default)]
    stage_time: Cow<'a, str>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Audit<'a> {
    time: Option<Timestamp>,
    stage_time: Option<Timestamp>,
    audit_id: Cow<'a, str>,
    stage: Cow<'a, str>,
    level: Cow<'a, str>,
    verb: Cow<'a, str>,
    user: Cow<'a, str>,
    groups: Vec<String>,
    impersonated_user: String,
    source_ips: Vec<String>,
    user_agent: Cow<'a, str>,
    api_group: Cow<'a, str>,
    resource: Cow<'a, str>,
    subresource: Cow<'a, str>,
    namespace: Cow<'a, str>,
    name: Cow<'a, str>,
    status_code: Option<i64>,
    status_reason: Cow<'a, str>,
    /// `allow` or `forbid`, from the `authorization.k8s.io/decision` annotation.
    decision: String,
    request_uri: Cow<'a, str>,
    /// For `exec` and `attach`: the command, from the `command` query parameters.
    command: String,
    /// `exec`, `attach`, `portforward`, `secret_read`, `change`, `anonymous` or empty.
    category: &'static str,
}

/// Cluster components talk to the API server constantly; their requests are not events.
fn system_component(user: &str) -> bool {
    ["system:node:", "system:kube-", "system:apiserver", "system:k3s-", "k3s-", "system:serviceaccount:kube-system:"]
        .iter()
        .any(|p| user.starts_with(p))
        || user == "system:node"
}

fn category(user: &str, groups: &[String], verb: &str, resource: &str, subresource: &str) -> &'static str {
    if user == "system:anonymous" || groups.iter().any(|g| g == "system:unauthenticated") {
        return "anonymous";
    }
    if system_component(user) {
        return "";
    }
    match (resource, subresource, verb) {
        ("pods", "exec", _) => "exec",
        ("pods", "attach", _) => "attach",
        ("pods", "portforward", _) => "portforward",
        ("secrets", _, "get" | "list" | "watch") => "secret_read",
        (
            "pods" | "roles" | "rolebindings" | "clusterroles" | "clusterrolebindings",
            "",
            "create" | "delete" | "deletecollection",
        ) => "change",
        ("roles" | "rolebindings" | "clusterroles" | "clusterrolebindings", "", "update" | "patch") => "change",
        _ => "",
    }
}

/// `%XX` and `+` decoding of one query value.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = |k: usize| bytes.get(k).and_then(|c| (*c as char).to_digit(16));
        match b {
            b'%' => match (hex(i + 1), hex(i + 2)) {
                (Some(hi), Some(lo)) => {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                _ => out.push(b),
            },
            b'+' => out.push(b' '),
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn exec_command(uri: &str) -> String {
    let Some((_, query)) = uri.split_once('?') else { return String::new() };
    let words: Vec<String> = query.split('&').filter_map(|p| p.strip_prefix("command=")).map(percent_decode).collect();
    words.join(" ")
}

impl Record for Audit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let kind = match self.category {
            "exec" | "attach" | "portforward" => "k8s_exec",
            "secret_read" => "k8s_secret_read",
            "change" => "k8s_change",
            "anonymous" => "k8s_anonymous",
            _ => return None.into_iter(),
        };
        let target = format!("{}/{}", self.namespace, self.name);
        let from = self.source_ips.first().map_or("", String::as_str);
        let what = match self.category {
            "exec" | "attach" | "portforward" => {
                format!("{} {} {target} [{}] {}", self.user, self.category, self.stage, self.command)
            }
            "secret_read" => format!("{} {} secrets {target}", self.user, self.verb),
            "change" => format!("{} {} {} {target}", self.user, self.verb, self.resource),
            _ => format!("anonymous {} {}", self.verb, self.request_uri),
        };
        let code = self.status_code.map_or(String::new(), |c| format!(" -> {c}"));
        self.time.map(|t| Event::new(t, kind, format!("{what} from {from}{code}"))).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let e: Event_ = match serde_json::from_slice(line.bytes) {
            Ok(e) => e,
            Err(err) => {
                sink.warn(format!("offset {}: not an audit event: {err}", line.offset));
                return Ok(());
            }
        };
        let time_of = |t: &str| parse_iso8601(t.as_bytes()).and_then(|(t, _)| t.recorded());
        let object = e.object_ref.unwrap_or_default();
        let category = category(&e.user.username, &e.user.groups, &e.verb, &object.resource, &object.subresource);
        let status = e.response_status.unwrap_or_default();
        let command = if matches!(category, "exec" | "attach") { exec_command(&e.request_uri) } else { String::new() };
        let record = Audit {
            time: time_of(&e.received),
            stage_time: time_of(&e.stage_time),
            audit_id: e.audit_id,
            stage: e.stage,
            level: e.level,
            verb: e.verb,
            user: e.user.username,
            groups: e.user.groups,
            impersonated_user: e.impersonated_user.map(|u| u.username.into_owned()).unwrap_or_default(),
            source_ips: e.source_ips,
            user_agent: e.user_agent,
            api_group: object.api_group,
            resource: object.resource,
            subresource: object.subresource,
            namespace: object.namespace,
            name: object.name,
            status_code: status.code,
            status_reason: status.reason,
            decision: e.annotations.get("authorization.k8s.io/decision").cloned().unwrap_or_default(),
            request_uri: e.request_uri,
            command,
            category,
        };
        sink.emit(Loc::Offset(line.offset), &record)
    })
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::{expected, file_bytes, records};
    use super::*;
    use crate::testing::run;
    use std::collections::BTreeMap;

    fn audit(flavor: &str) -> (String, Vec<u8>) {
        let path = if flavor == "k3s" {
            "var/lib/rancher/k3s/server/logs/audit.log"
        } else {
            "var/log/kubernetes/audit/audit.log"
        };
        (path.to_string(), file_bytes(flavor, "audit.log"))
    }

    /// Both real audit logs: one record per line, the categories counted by the Python rules
    /// that built `expected.json` (no shared code), and one timeline event per categorised record.
    #[test]
    fn real_audit_logs_categorise_like_the_independent_count() {
        for flavor in ["k3s", "kind"] {
            let (path, data) = audit(flavor);
            let out = run(&ARTIFACT, &path, &data, 0);
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{flavor}: {out}");
            let rows = records(&out);
            let truth = expected(flavor);
            assert_eq!(rows.len() as u64, truth["audit"]["lines"].as_u64().unwrap(), "{flavor}");
            let mut seen: BTreeMap<String, u64> = BTreeMap::new();
            for r in &rows {
                let c = r["category"].as_str().unwrap();
                if !c.is_empty() {
                    *seen.entry(c.to_string()).or_default() += 1;
                }
            }
            let want: BTreeMap<String, u64> = truth["audit"]["categories"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
                .collect();
            assert_eq!(seen, want, "{flavor}");
            let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
            assert_eq!(timeline.lines().count() as u64 - 1, want.values().sum::<u64>(), "{flavor}");
        }
    }

    /// `kubectl exec` goes through the API server as a request for the `exec` subresource whose
    /// query carries the command: it must come out of the record, and it was run by the admin.
    #[test]
    fn exec_into_a_pod_gives_the_command_and_the_user() {
        let (path, data) = audit("kind");
        let rows = records(&run(&ARTIFACT, &path, &data, 0));
        let execs: Vec<_> = rows.iter().filter(|r| r["category"] == "exec").collect();
        assert!(execs.iter().all(|r| r["subresource"] == "exec"
            && r["resource"] == "pods"
            && r["name"] == "execer"
            && r["namespace"] == "default"));
        let with_command = execs
            .iter()
            .find(|r| r["command"].as_str().unwrap().contains("exec-marker"))
            .expect("the exec command is in the record");
        assert_eq!(with_command["command"], "sh -c id; echo exec-marker");
        assert_eq!(with_command["user"], "kubernetes-admin");
        assert!(with_command["user_agent"].as_str().unwrap().starts_with("kubectl/"));
        // `kubectl cp` runs `tar` through exec too.
        assert!(execs.iter().any(|r| r["command"].as_str().unwrap().starts_with("tar ")));
    }

    #[test]
    fn a_non_system_users_changes_secret_reads_and_anonymous_requests() {
        let (path, data) = audit("kind");
        let rows = records(&run(&ARTIFACT, &path, &data, 0));
        let alice: Vec<(String, String, String)> = rows
            .iter()
            .filter(|r| r["user"] == "alice" && r["category"] == "change")
            .map(|r| {
                (
                    r["verb"].as_str().unwrap().into(),
                    r["resource"].as_str().unwrap().into(),
                    r["name"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert!(alice.contains(&("create".into(), "pods".into(), "alice-pod".into())), "{alice:?}");
        assert!(alice.contains(&("create".into(), "rolebindings".into(), "bob-view".into())), "{alice:?}");
        assert!(alice.contains(&("delete".into(), "pods".into(), "alice-pod".into())), "{alice:?}");
        assert_eq!(rows.iter().find(|r| r["user"] == "alice").unwrap()["groups"][0], "devs");
        let secret = rows.iter().find(|r| r["category"] == "secret_read" && r["name"] == "db-pass").unwrap();
        assert_eq!((secret["resource"].as_str(), secret["user"].as_str()), (Some("secrets"), Some("kubernetes-admin")));
        let anon: Vec<_> = rows.iter().filter(|r| r["category"] == "anonymous").collect();
        assert_eq!(anon.len(), 2);
        assert!(anon.iter().all(|r| r["user"] == "system:anonymous" && r["source_ips"][0].is_string()));
        // Kubernetes' own components never reach the timeline.
        assert!(rows
            .iter()
            .filter(|r| r["user"].as_str().unwrap().starts_with("system:node:"))
            .all(|r| r["category"] == ""));
    }

    #[test]
    fn rotations_damaged_lines_and_empty_input() {
        let line = br#"{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a","stage":"ResponseComplete","verb":"get","user":{"username":"bob"},"objectRef":{"resource":"secrets","namespace":"n","name":"s"},"requestReceivedTimestamp":"2026-11-12T10:00:00.5Z","sourceIPs":["203.0.113.4"],"responseStatus":{"code":200}}"#;
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut w = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            w.write_all(line).unwrap();
            w.write_all(b"\n").unwrap();
            w.finish().unwrap();
        }
        let out = run(&ARTIFACT, "var/log/kubernetes/audit/audit-2026-11-12T10-00-00.000.log.gz", &gz, 0);
        assert_eq!(records(&out)[0]["category"], "secret_read");
        assert!(out.contains("bob get secrets n/s from 203.0.113.4 -> 200"), "{out}");
        let mut bad = line.to_vec();
        bad.extend(b"\nnot json\n{\"verb\":5}\n");
        let out = run(&ARTIFACT, "var/log/kubernetes/audit/audit.log", &bad, 0);
        assert_eq!(out.matches("--- warning").count(), 2, "{out}");
        assert_eq!(records(&out).len(), 1);
        assert_eq!(run(&ARTIFACT, "var/log/kubernetes/audit/audit.log", b"", 0), "");
    }

    #[test]
    fn mutated_audit_logs_never_panic() {
        let (path, real) = audit("kind");
        let real = &real[..real.len().min(200_000)];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..400 {
            let mut data = real.to_vec();
            for _ in 0..=(round % 8) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            if round % 4 == 0 {
                data.truncate((next() as usize) % data.len());
            }
            run(&ARTIFACT, &path, &data, 0);
        }
    }
}
